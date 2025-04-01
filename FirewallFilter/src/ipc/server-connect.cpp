#include "server-connect.hpp"
#include "server-connect.hpp"
#include <dlfcn.h>
#include <iostream>
#include <string>
#include <cstring>

using namespace std;

typedef void* (*CreateInstanceFunc)();
typedef void (*DestroyInstanceFunc)(void*);
typedef int (*ConnectFunc)(void*, long, const char*, char*, size_t);

bool connectToManager() {
    const char* soPath = "/home/ariel/Documents/github/Firewall/FirewallSharedObject/libFirewallSharedObject.so";

    void* handle = dlopen(soPath, RTLD_LAZY);
    if (!handle) {
        cerr << "Failed to load shared object: " << dlerror() << endl;
        return false;
    }

    dlerror(); // Clear any existing error

    // Load functions
    auto createInstance = (CreateInstanceFunc)dlsym(handle, "create_fwso_instance");
    auto destroyInstance = (DestroyInstanceFunc)dlsym(handle, "destroy_fwso_instance");
    auto fwConnect = (ConnectFunc)dlsym(handle, "fw_connect");

    const char* dlsym_error = dlerror();
    if (dlsym_error) {
        cerr << "Failed to load symbol: " << dlsym_error << endl;
        dlclose(handle);
        return false;
    }

    // Create instance
    void* instance = createInstance();
    if (!instance) {
        cerr << "Failed to create FWSO instance." << endl;
        dlclose(handle);
        return false;
    }

    // Prepare login parameters
    long firewallID = 0; // You can modify as needed
    const char* key = "blabn";
    char response[1024] = {0};

    cout << "Attempting to connect to manager..." << endl;

    int result = fwConnect(instance, firewallID, key, response, sizeof(response));
    if (result == 0) {
        cout << "Response received. Response: " << response << endl;
    } else {
        cerr << "Login failed. Error code: " << result << endl;
    }

    destroyInstance(instance);
    dlclose(handle);
    return result == 0;
}
