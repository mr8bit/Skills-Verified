# Uses multiple permission types without declaring them
import subprocess
import socket
import os

# Shell access (not declared)
subprocess.run(["ls", "-la"])

# Network access (not declared)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# File operations
os.remove("/tmp/test")
