#include <unistd.h>
#include <list>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

int main()
{
  list<string> ssidList {
    "1.길길이",
    "2.엄청잘생김",
    "3.서울에서제일잘생김",
    "4.한국에서제일잘생김",
    "5.세상에서제일잘생김",
    "6.완전짱인듯"
  };
  list<string> macList {
    "00:11:22:33:44:51",
    "00:11:22:33:44:52",
    "00:11:22:33:44:53",
    "00:11:22:33:44:54",
    "00:11:22:33:44:55",
    "00:11:22:33:44:56"
  };
  list<string>::iterator it = ssidList.begin();
  list<string>::iterator mac = macList.begin();
  while (true) {
    RadioTap tap;

    Dot11::address_type ap        = *mac;
    Dot11::address_type broadcast = "ff:ff:ff:ff:ff:ff";
    Dot11Beacon beacon(broadcast, ap);
    beacon.addr3(beacon.addr2());
    beacon.addr4(ap);
    beacon.ssid(*it);
    //beacon.interval(0.8);
    beacon.ds_parameter_set(10);
    beacon.supported_rates({ 1.0f, 5.5f, 11.0f });
    tap.inner_pdu(beacon);

    PacketSender sender("wlxec086b1353a9");
    sender.send(tap);
    usleep(1000);

    if (++it == ssidList.end())
      it = ssidList.begin();
    if (++mac == macList.end())
      mac = macList.begin();
  }
}
