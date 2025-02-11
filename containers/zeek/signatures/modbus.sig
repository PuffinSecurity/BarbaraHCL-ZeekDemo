# Function code handling
signature modbus_function_code {
    ip-proto == tcp
    dst-port == 502
    payload /.{7}\x80.{1}\x01/
    event "Modbus: Function code handling detected"
}

# Diagnostics device
signature modbus_diagnostics_device {
    ip-proto == tcp
    dst-port == 502
    payload /.{7}\x08/
    event "Modbus: Diagnostics device detected"
}
