import socket

from bacpypes.apdu import (AbortPDU, IAmRequest, PropertyReference,
                           ReadAccessSpecification, ReadPropertyACK,
                           ReadPropertyMultipleRequest, ReadPropertyRequest,
                           WhoIsRequest, WritePropertyRequest)
from bacpypes.app import BIPSimpleApplication
from bacpypes.basetypes import PropertyIdentifier, ServicesSupported
from bacpypes.constructeddata import Any, Array
from bacpypes.iocb import IOCB
from bacpypes.object import get_datatype
from bacpypes.pdu import Address
from bacpypes.service.device import LocalDeviceObject


class BACNetClientRead(Block):

    version = VersionProperty('0.1.0')
    name = StringProperty(title='BACNet Object Name')
    id = IntProperty(title='Object ID Number')
    instance = IntProperty(title='Object Instance Number')
    address = StringProperty(title='IP Address', default='127.0.0.1')
    vendor_id = IntProperty(title='Client Vendor ID')
    max_apdu_length = IntProperty(title='Max APDU Length', default=1024)
    segmentation = StringProperty(title='Segmentation Supported',
                                  default='segmentedBoth')
    array_index = IntProperty(title='Data index')
    property = StringProperty(title='Name of Property')

    def configure(self):
        # bacnet device config
        self.ldo = LocalDeviceObject(
            objectName=self.name()
            objectIdentifier=int(self.id()),
            maxApduLengthAccepted=int(self.max_apdu_length()),
            segmentationSupported=self.segmentation(),
            vendorIdentifier=int(self.vendor_id())
        )

        # Send an empty support string
        pss = ServicesSupported()
        ldo.protocolServicesSupported = pss.value

        info = self.address()
        hostname = ""
        for i, c in enumerate(info):
            if c is '/' or c is ':':
                break
            hostname += c
        suffix = info[i:]

        addr = socket.gethostbyname(hostname)
        self.this_application = SimpleApplication(self.ldo, addr + suffix)

    def process_signals(self, signals):
        ouput_signal = []

        if not self.this_application._started:
            self.logger.error('BACnet stack not running')

        for signal in signals:
            value = self._read()
            output_signal.append(value)

        self.notify_signals(output_signal)

    def _read(self):
        """
        :param args: String with <addr> <type> <inst> <prop> [ <indx> ]
        :returns: data read from device (str representing data like 10 or True)
        """

        args_split = args.split()

        self.log_title("Read property {} {} {} {}".format(self.address(), self.))

        vendor_id = self.vendor_id()
        bacoid = self.id()

        try:
            iocb = IOCB(self._build_rp_request(
                [self.address(), self.obj_type(), self.obj_instance(), self.property()],
                arr_index=self.arr_index(),
                vendor_id=vendor_id,
                bacoid=bacoid)
            )
            deferred(self.this_application.request_io, iocb)
            self.logger.debug("{:<20} {!r}".format('iocb', iocb))

        except ReadPropertyException as error:
            self.logger.exception("exception: {!r}".format(error))

        iocb.wait()

        if iocb.ioResponse:     # successful response
            apdu = iocb.ioResponse

            if not isinstance(apdu, ReadPropertyACK):
                self.logger.warning("Not an ack, see debug for more infos.")
                self.logger.debug(
                    "Not an ack. | APDU : {} / {}".format((apdu, type(apdu))))
                return

            # find the datatype
            datatype = get_datatype(
                apdu.objectIdentifier[0], apdu.propertyIdentifier, vendor_id=vendor_id)
            if not datatype:
                raise TypeError("unknown datatype")

            if issubclass(datatype, Array) and (apdu.propertyArrayIndex is not None):
                if apdu.propertyArrayIndex == 0:
                    value = apdu.propertyValue.cast_out(Unsigned)
                else:
                    value = apdu.propertyValue.cast_out(datatype.subtype)
            else:
                value = apdu.propertyValue.cast_out(datatype)


            self.logger.info(
                "{!r:<20} {!r:<20}".format(
                    value,
                    datatype))
            return value

    def _build_rp_request(self):
        addr = self.address()
        obj_type = self.obj_type()
        prop_id = self.property_id()
        vendor_id = self.vendor_id()
        bacoid = self.id()

        if obj_type.isdigit():
            obj_type = int(self.obj_type)
        elif not get_object_class(obj_type):
            raise ValueError("unknown object type")

        obj_inst = int(self.instance())

        if prop_id.isdigit():
            prop_id = int(prop_id)
        datatype = get_datatype(obj_type, prop_id, vendor_id=vendor_id)
        if not datatype:
            raise ValueError("invalid property for object type")

        # build a request
        request = ReadPropertyRequest(
            objectIdentifier=(obj_type, obj_inst),
            propertyIdentifier=prop_id,
            propertyArrayIndex=self.array_index(),
        )
        request.pduDestination = Address(self.address())

        self.logger.debug("{:<20} {!r}".format(
            'REQUEST', request))
        return request
