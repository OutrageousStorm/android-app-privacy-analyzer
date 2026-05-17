#!/usr/bin/env python3
import subprocess, sys, argparse

FRIDA_SCRIPT = """
Java.perform(function() {
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function() {
        console.log("[NETWORK] " + this.getProtocol() + " → " + this.getHost() + ":" + this.getPort());
        return this.openConnection.call(this);
    };
    console.log("[Network Monitor] Active");
});
"""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True)
    args = parser.parse_args()
    
    with open("/tmp/spy.js", "w") as f:
        f.write(FRIDA_SCRIPT)
    
    print(f"Monitoring {args.app}...")
    subprocess.run(f'frida -U -f "{args.app}" -l /tmp/spy.js --no-pause', shell=True)

if __name__ == "__main__":
    main()
