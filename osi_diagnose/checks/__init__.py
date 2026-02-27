from osi_diagnose.checks.base import LayerCheck
from osi_diagnose.checks.l1_physical import Layer1PhysicalCheck
from osi_diagnose.checks.l2_datalink import Layer2DataLinkCheck
from osi_diagnose.checks.l3_network import Layer3NetworkCheck
from osi_diagnose.checks.l4_transport import Layer4TransportCheck
from osi_diagnose.checks.l5_session import Layer5SessionCheck
from osi_diagnose.checks.l6_presentation import Layer6PresentationCheck
from osi_diagnose.checks.l7_application import Layer7ApplicationCheck


ALL_CHECKS: list[type[LayerCheck]] = [
    Layer1PhysicalCheck,
    Layer2DataLinkCheck,
    Layer3NetworkCheck,
    Layer4TransportCheck,
    Layer5SessionCheck,
    Layer6PresentationCheck,
    Layer7ApplicationCheck,
]
