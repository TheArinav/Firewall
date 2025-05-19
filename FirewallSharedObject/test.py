import ctypes
import os

def test():
    SO_PATH = "/home/ariel/Documents/github/Firewall/FirewallSharedObject/libFirewallSharedObject.so"

    if not os.path.exists(SO_PATH):
        print(f"Error: Shared object '{SO_PATH}' not found.")
        exit(1)

    try:
        # Load the shared object
        fwso = ctypes.CDLL(SO_PATH)

        # Set up function prototypes
        fwso.create_fwso_instance.restype = ctypes.c_void_p
        fwso.destroy_fwso_instance.argtypes = [ctypes.c_void_p]
        fwso.fw_connect.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        fwso.fw_connect.restype = ctypes.c_int

        # Create an instance of the API
        instance = fwso.create_fwso_instance()

        # Prepare test parameters
        firewall_id = 0  # Example ID
        key = "blabn".encode("utf-8")
        response_buffer = ctypes.create_string_buffer(1024)

        print("Attempting to connect to the firewall service...")

        # Call the function with the correct number of arguments
        result = fwso.fw_connect(instance, firewall_id, key, response_buffer, ctypes.sizeof(response_buffer))

        if result == 0:
            print(f"Successfully connected. Response: {response_buffer.value.decode('utf-8')}")
        else:
            print(f"Failed to connect to the firewall service. Error code: {result}")

        # Set up fw_test_req function prototype
        fwso.fw_test_req.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
        fwso.fw_test_req.restype = ctypes.c_int

        # Call fw_test_req after fw_connect
        print("Testing general request...")

        test_response_buffer = ctypes.create_string_buffer(1024)
        test_result = fwso.fw_test_req(instance, test_response_buffer, ctypes.sizeof(test_response_buffer))

        if test_result == 0:
            print(f"fw_test_req succeeded. Response: {test_response_buffer.value.decode('utf-8')}")
        else:
            print(f"fw_test_req failed. Error code: {test_result}")

        # Clean up the instance
        fwso.destroy_fwso_instance(instance)

    except AttributeError as e:
        print(f"Error: Function not found in shared object - {e}")
    except OSError as e:
        print(f"Error: Unable to load shared object - {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    test()