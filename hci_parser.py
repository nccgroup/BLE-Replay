from btsnoop.btsnoop.android.snoopphone import SnoopPhone
import binascii
import util
import btsnoop.btsnoop.btsnoop.btsnoop as bts
import btsnoop.btsnoop.bt.hci_uart as hci_uart
import btsnoop.btsnoop.bt.hci_acl as hci_acl
import btsnoop.btsnoop.bt.l2cap as l2cap
import btsnoop.btsnoop.bt.att as att


class ATTWriteParser:
    """HCI log fetching/parsing component that uses btsnoop"""

    def __init__(self):
        self.snoop_file = None
        self.att_writes = []
        self.records = []

    def fetch_from_phone(self, output_filename=None):
        """Fetch btsnoop file from connected Android device
        adb required, don't pass a filename if you don't
        want to store the log locally
        """
        phone = SnoopPhone()
        try:
            self.snoop_file = phone.pull_btsnoop(output_filename)
        except ValueError:
            print "connect an Android device..."
            raise
        except Exception as e:
            print e.message

    def load_file(self, input_filename=None):
        """Load a btsnoop file from disk"""
        if input_filename:
            self.snoop_file = input_filename
        else:
            raise ValueError("Must specify a valid filename for load_file")

    def get_records(self):
        """Parse the btsnoop file into a dictionary of records"""
        if not self.snoop_file:
            raise ValueError("Must load a btsnoop file to get records")
            return

        try:
            records = bts.parse(self.snoop_file)
        except Exception as e:
            print e.message
            return None

        self.records = records
        return records

    def parse_att_writes(self):
        """Get a list of ATT write requests in the log"""
        self.att_writes = []
        self.get_records()
        for record in self.records:

            # seq_nbr = record[0]
            hci_pkt_type, hci_pkt_data = hci_uart.parse(record[4])

            if hci_pkt_type == hci_uart.ACL_DATA:

                hci_data = hci_acl.parse(hci_pkt_data)
                l2cap_length, l2cap_cid, l2cap_data = l2cap.parse(hci_data[2],
                                                                  hci_data[4])

                if l2cap_cid == l2cap.L2CAP_CID_ATT:

                    att_opcode, att_data = att.parse(l2cap_data)
                    cmd_evt_l2cap = att.opcode_to_str(att_opcode)

                    if 'Write_Request' in cmd_evt_l2cap\
                            or 'Write_Command' in cmd_evt_l2cap:

                        data = binascii.hexlify(att_data)
                        handle = data[2:4] + data[0:2]
                        self.att_writes.append([handle, data[4:], [], 1])
        return self.att_writes

    def write_to_file(self, output_filename=None):
        """Write the data to a file for manual modification before replay"""
        if not output_filename:
            raise ValueError("Must specify an output filename")

        util.replay_file_write(self.att_writes, output_filename)

    def pretty_print(self):
        """Pretty print the data to standard out"""
        try:
            from prettytable import PrettyTable
        except:
            print "prettytable required for this feature"
            return

        table = PrettyTable(['No.', 'Time', 'Handle', 'Data'])
        table.align["Handle"] = 'l'
        table.align["Data"] = 'l'

        for r in self.att_writes:

            data = len(r[3]) > 30 and r[3][:30] + "..." or r[3]
            time = r[1].strftime("%b-%d %H:%M:%S.%f")
            table.add_row([r[0], time, r[2], data])

        print table
