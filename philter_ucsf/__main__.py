import argparse
import re 
import pickle
import gzip
import json
import sys


def _strtobool(value):
    if isinstance(value, bool):
        return value
    s = str(value).lower().strip()
    if s in ("yes", "true", "t", "1", "y", "on"):
        return True
    if s in ("no", "false", "f", "0", "n", "off"):
        return False
    raise ValueError(f"invalid truth value: {value!r}")


def main():
    # get input/output/filename
    help_str = """ Philter -- PHI filter for clinical notes """
    ap = argparse.ArgumentParser(description=help_str)
    ap.add_argument("-i", "--input", default="./data/i2b2_notes/",
                    help="Path to the directory or the file that contains the PHI note, the default is ./data/i2b2_notes/",
                    type=str)
    ap.add_argument("-a", "--anno", default="./data/i2b2_anno/",
                    help="Path to the directory or the file that contains the PHI annotation, the default is ./data/i2b2_anno/",
                    type=str)
    ap.add_argument("-o", "--output", default="./data/i2b2_results/",
                    help="Path to the directory to save the PHI-reduced notes in, the default is ./data/i2b2_results/",
                    type=str)
    ap.add_argument("-f", "--filters", default="./configs/integration_1.json",
                    help="Path to our config file, the default is ./configs/integration_1.json",
                    type=str)
    ap.add_argument("-x", "--xml", default="./data/phi_notes.json",
                    help="Path to the json file that contains all xml data",
                    type=str)
    ap.add_argument("-c", "--coords", default="./data/coordinates.json",
                    help="Path to the json file that contains the coordinate map data",
                    type=str)
    ap.add_argument("--eval_output", default="./data/phi/",
                    help="Path to the directory that the detailed eval files will be outputted to",
                    type=str)
    ap.add_argument("-v", "--verbose", default=True,
                    help="When verbose is true, will emit messages about script progress",
                    type=lambda x: _strtobool(x))
    ap.add_argument("-e", "--run_eval", default=True,
                    help="When run_eval is true, will run our eval script and emit summarized results to terminal",
                    type=lambda x: _strtobool(x))
    ap.add_argument("-t", "--freq_table", default=False,
                    help="When freqtable is true, will output a unigram/bigram frequency table of all note words and their PHI/non-PHI counts",
                    type=lambda x: _strtobool(x)) 
    ap.add_argument("-n", "--initials", default=True,
                    help="When initials is true, will include initials PHI in recall/precision calculations",
                    type=lambda x: _strtobool(x)) 
    ap.add_argument("--stanfordner", default="/usr/local/stanford-ner/",
                    help="Path to Stanford NER, the default is /usr/local/stanford-ner/",
                    type=str)
    ap.add_argument("--outputformat", default="asterisk",
                    help="Define format of annotation, allowed values are \"asterisk\", \"i2b2\". Default is \"asterisk\"",
                    type=str)
    ap.add_argument("--ucsfformat", default=False,
                    help="When ucsfformat is true, will adjust eval script for slightly different xml format",
                    type=lambda x: _strtobool(x))
    ap.add_argument("--prod", default=False,
                    help="When prod is true, this will run the script with output in i2b2 xml format without running the eval script",
                    type=lambda x: _strtobool(x))
    ap.add_argument("--cachepos", default=None,
                    help="Path to a directoy to store/load the pos data for all notes. If no path is specified then memory caching will be used.",
                    type=str)
    ap.add_argument("--profile-map-coordinates", default=False,
                    help="Print per-pattern timings for map_coordinates / map_coordinates_text (stderr-style to stdout)",
                    type=lambda x: _strtobool(x))
    ap.add_argument(
        "--phi-types",
        default=None,
        dest="phi_types",
        help="Comma-separated phi types to apply for exclude (redaction) rules only; "
        "whitelist rules always run. Omit for all types. "
        "Known: DATE,Patient_Social_Security_Number,Email,Provider_Address_or_Location,Age,Name,OTHER",
        type=str,
    )
    ap.add_argument(
        "--patterns",
        default=None,
        dest="patterns",
        help="Comma-separated pattern titles and/or slugs (see --list-exclude-patterns). "
        "When set, only these exclude rules contribute to redaction; whitelist rules still run. "
        "Combined with --phi-types using AND logic.",
        type=str,
    )
    ap.add_argument(
        "--list-exclude-patterns",
        action="store_true",
        help="Print all exclude rules from -f/--filters with phi_type (OTHER = no phi_type in JSON) and exit.",
    )

    ap.add_argument(
        "--hipaa-report",
        action="store_true",
        help="Print heuristic coverage of the 18 HIPAA identifiers for -f/--filters and exit.",
    )
    ap.add_argument(
        "--list-hipaa-groups",
        action="store_true",
        help="Print exclude rules from -f grouped by HIPAA identifier (1–18); use to pick --hipaa-ids.",
    )
    ap.add_argument(
        "--hipaa-ids",
        default=None,
        dest="hipaa_ids",
        help="Comma-separated HIPAA Safe Harbor identifiers to redact: numeric 1–18 and/or "
        "keys (name, geo_substate, dates, phone, fax, email, ssn, mrn, health_plan, account, "
        "cert_license, vehicle, device_serial, url, ip, biometric, photo, other_unique). "
        "Aliases: address, telephone, social_security, … Only exclude rules mapped to these "
        "ids run (AND with --phi-types / --patterns if set). See --list-hipaa-groups.",
        type=str,
    )
    ap.add_argument(
        "--hipaa-preset",
        default=None,
        choices=["minimal", "minimal_plus"],
        dest="hipaa_preset",
        help="minimal = only a greedy minimal set of exclude rules that touches each HIPAA id "
        "1–18 possible for this filter (heuristic). minimal_plus = run every exclude rule "
        "(maximum PHI removal) while reporting what the greedy HIPAA-only floor would be. "
        "Overrides --patterns and --hipaa-ids.",
        type=str,
    )

    args = ap.parse_args()

    if args.list_hipaa_groups:
        from philter_ucsf.hipaa import hipaa_pattern_groups_report

        hipaa_pattern_groups_report(args.filters)
        return

    if args.hipaa_report:
        from philter_ucsf.hipaa import hipaa_coverage_report

        hipaa_coverage_report(args.filters)
        return

    if args.list_exclude_patterns:
        from philter_ucsf.pattern_list import summarize_filter_patterns

        summarize_filter_patterns(args.filters)
        return

    from philter_ucsf.philter import Philter

    run_eval = args.run_eval
    verbose = args.verbose

    active_phi_types = None
    if args.phi_types:
        active_phi_types = [x.strip() for x in args.phi_types.split(",") if x.strip()]

    active_patterns = None
    if args.patterns:
        active_patterns = [x.strip() for x in args.patterns.split(",") if x.strip()]

    active_hipaa = args.hipaa_ids

    if args.hipaa_preset:
        if args.patterns or args.hipaa_ids:
            print(
                "Warning: --hipaa-preset overrides --patterns and --hipaa-ids.",
                file=sys.stderr,
            )
        active_patterns = None
        active_hipaa = None

    if args.prod:
        run_eval = False
        verbose = False
        outputformat = "i2b2"
        # filters = "./configs/philter_alpha.json"
        philter_config = {
            "verbose":verbose,
            "run_eval":run_eval,
            "finpath":args.input,
            "foutpath":args.output,
            "outformat":outputformat,
            "filters":args.filters,
            "cachepos":args.cachepos,
            "profile_map_coordinates": args.profile_map_coordinates,
            "active_phi_types": active_phi_types,
            "active_patterns": active_patterns,
            "active_hipaa_identifiers": active_hipaa,
            "hipaa_preset": args.hipaa_preset,
        }

    else:
        philter_config = {
            "verbose":args.verbose,
            "run_eval":args.run_eval,
            "freq_table":args.freq_table,
            "initials":args.initials,
            "finpath":args.input,
            "foutpath":args.output,
            "outformat":args.outputformat,
            "ucsfformat":args.ucsfformat,
            "anno_folder":args.anno,
            "filters":args.filters,
            "xml":args.xml,
            "coords":args.coords,
            "eval_out":args.eval_output,
            "cachepos":args.cachepos,
            "stanford_ner_tagger": {
                "classifier":args.stanfordner+"classifiers/english.all.3class.distsim.crf.ser.gz",
                "jar":args.stanfordner+"stanford-ner.jar",
                "download":True,
            },
            "profile_map_coordinates": args.profile_map_coordinates,
            "active_phi_types": active_phi_types,
            "active_patterns": active_patterns,
            "active_hipaa_identifiers": active_hipaa,
            "hipaa_preset": args.hipaa_preset,
        }
   
    if verbose:
        print("RUNNING ", philter_config['filters'])


    filterer = Philter(philter_config)

    #map any sets, pos and regex groups we have in our config
    filterer.map_coordinates()

    
    #transform the data 
    #Priority order is maintained in the pattern list
    filterer.transform()

    #evaluate the effectiveness
    if run_eval and args.outputformat == "asterisk":
        filterer.eval(
            philter_config,
            in_path=args.output,
            anno_path=args.anno,
            anno_suffix=".txt",
            fn_output = "data/phi/fn.txt",
            fp_output = "data/phi/fp.txt",
            summary_output="./data/phi/summary.json",
            phi_matcher=re.compile(r"\*+"),
            pre_process=r":|\,|\-|\/|_|~", #characters we're going to strip from our notes to analyze against anno
            only_digits=False,
            pre_process2= r"[^a-zA-Z0-9]",
            punctuation_matcher=re.compile(r"[^a-zA-Z0-9\*]"))

# error analysis
        
if __name__ == "__main__":
    main()
