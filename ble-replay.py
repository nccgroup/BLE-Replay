import hci_parser
import argparse
import util
import json
import sys


def create_help():

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface",
                        help="Device interface (like hci0), "
                        "retrieve using 'hcitool dev'")
    parser.add_argument("-d", "--addr",
                        help="Device address, specified like 0E:3F:00:01:B2:0A")
    parser.add_argument("-s", "--seclevel",
                        help="Security level ('low', 'medium', 'high')",
                        default="low")
    parser.add_argument("-t", "--addr_type",
                        help="Address type ('public', 'random')",
                        default="random")
    parser.add_argument("-p", "--parse",
                        help="Parse replay data from an HCI log file")
    parser.add_argument("-if", "--infile",
                        help="Get replay data from a file created by this tool")
    parser.add_argument("-f", "--fetch",
                        help="Fetch replay data from Android device using adb",
                        action="store_true")
    parser.add_argument("-r", "--replay",
                        help="Replay the data, requires -f or -if",
                        action="store_true")
    parser.add_argument("-of", "--outfile",
                        help="Output file to write replay data to")
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    return args


def args_valid(args):

    if args.replay:
        if not (args.iface and args.addr):
            print "You must specify an interface and device address"
            return False
        if args.seclevel not in ["low", "medium", "high"]:
            print "Security level must be low, medium, or high"
            return False
        if args.addr_type not in ["public", "random"]:
            print "Address type must be public or random"
            return False
    elif not args.outfile:
        print "You must specify an output option (-r, -of)"
        return False
    if not (args.parse or args.fetch or args.infile):
        print "You must specific an input option (-if, -p, -f)"
        return False

    return True


def main():

    args = create_help()
    if not args_valid(args):
        return
    replay_data = []
    if args.infile:
        with open(args.infile, 'r') as infile:
            for line in infile:
                replay_data.append(json.loads(line))
    else:
        logparser = hci_parser.ATTWriteParser()
        if args.parse:
            logparser.load_file(args.parse)
        elif args.fetch:
            try:
                logparser.fetch_from_phone()
            except:
                return
        replay_data = logparser.parse_att_writes()
        if args.outfile:
            logparser.write_to_file(args.outfile)

    if args.replay:
        util.gatt_writes(args.iface, args.addr, args.seclevel,
                         args.addr_type, replay_data)
        return
    elif args.outfile:
        return

main()
