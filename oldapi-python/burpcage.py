import re
from burp import IBurpExtender, IHttpListener, IBurpExtenderCallbacks, IExtensionHelpers, IResponseInfo, IHttpRequestResponse
import urllib2

EXTENSION_NAME = 'burp-cage-python'
NIC_CAGE_IMG = 'https://assets-prd.ignimgs.com/2022/07/19/nicolas-cage-in-con-air-1658251738731.jpg'
NIC_CAGE_IMG_TYPE = 'image/jpeg'
CONTENT_TYPE = 'Content-Type'
REPLACE_CONTENT_TYPES = ['JPEG', 'PNG', 'GIF', 'SVG', 'image']

# Get the nic cage image
def get_nic_cage():
    return urllib2.urlopen(NIC_CAGE_IMG).read()


class BurpExtender(IBurpExtender, IHttpListener):
    extender_callbacks = None  # type: IBurpExtenderCallbacks
    extension_helpers = None  # type: IExtensionHelpers
    nic_cage = get_nic_cage()

    # Turn the response into a string
    def get_string_response(self, response_info, raw_bytes):
        # type: (IResponseInfo, array) -> str

        body_offset = response_info.getBodyOffset()
        return self.extension_helpers.bytesToString(raw_bytes[body_offset:])

    # IBurpExtender overridden function
    def registerExtenderCallbacks(self, extender_callbacks):
        # type: (IBurpExtenderCallbacks) -> None
        self.extender_callbacks = extender_callbacks
        self.extension_helpers = extender_callbacks.getHelpers()

        self.extender_callbacks.setExtensionName(EXTENSION_NAME)
        self.extender_callbacks.registerHttpListener(self)

    # IHttpListener overridden function
    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        # type: (int, bool, IHttpRequestResponse) -> None
        if message_info.getResponse() is None:
            return

        response_info = self.extension_helpers.analyzeResponse(
            message_info.getResponse())  # type: IResponseInfo

        # Ignore non-image MIME types
        if response_info.getStatedMimeType() not in REPLACE_CONTENT_TYPES:
            return

        # Copy headers into a new list, but replace the MIME type
        new_headers = []
        for x in response_info.getHeaders():
            if x.lower().startswith('{}:'.format(CONTENT_TYPE.lower())):
                x = '{}: {}'.format(CONTENT_TYPE, NIC_CAGE_IMG_TYPE)
            new_headers.append(x)

        # Replace the image response
        new_response = self.extension_helpers.buildHttpMessage(new_headers, self.nic_cage)
        message_info.setResponse(new_response)
