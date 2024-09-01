# 🕵️‍♂️ Inquisitor: ARP Poisoning Tool in Rust 🦀

Welcome to **Inquisitor**, a tool designed to demonstrate ARP poisoning attacks using Rust. This project includes a Dockerized environment for safe and controlled testing.

## 🔍 What is ARP Poisoning?

**ARP Poisoning** (or ARP Spoofing) is a network attack where a malicious actor sends forged ARP messages onto a local network. This causes incorrect IP-to-MAC address mappings, enabling the attacker to intercept, modify, or block traffic between devices on the network. In essence, the attacker can impersonate another device on the network.

## 🚀 How to Test Inquisitor

### Prerequisites

- Ensure **Docker** and **Docker Compose** are installed on your machine.

### Steps to Test

1. **Clone the Repository:**
   ```sh
   git clone https://github.com/your-username/inquisitor.git
   cd inquisitor
   ```

2. **Build and Start the Docker Infrastructure:**
   Use the `Makefile` to set up the testing environment.
   ```sh
   make all
   ```
   This command will:
   - Build and deploy three Docker containers: `attacker`, `victim1`, and `victim2`.
   - Create a custom network with predefined IP addresses for each container.

3. **Access the Attacker Container:**
   ```sh
   make attacker
   ```
   This command will open a shell inside the `attacker` container.

4. **Run the Inquisitor Tool:**

   The **Inquisitor** tool can be used manually or with a predefined alias:

   - **Manual Execution**:
     Inside the `attacker` container, you can run the tool directly by specifying the necessary arguments:
     ```sh
     inquisitor <IP-src> <MAC-src> <IP-target> <MAC-target> <interface>
     ```
     Example:
     ```sh
     inquisitor 192.168.1.3 02:42:C0:A8:01:03 192.168.1.2 02:42:C0:A8:01:02 eth0
     ```

   - **Using the Alias**:
     For convenience, an alias named `inquisitest` has been set up in the `attacker` container. This alias runs the Inquisitor tool with predefined arguments:
     ```sh
     inquisitest
     ```
     This will automatically launch the ARP spoofing attack, targeting `victim1` and `victim2`. The tool will capture and print the names of files transferred between them via FTP.

5. **Connect to the FTP Server:**

   To observe the attack in action, initiate file transfers between the victims:

   - **Access `victim2`:**
     ```sh
     make victim2
     ```

   - **Connect to `victim1`'s FTP server from `victim2`**:

     You can connect manually using `lftp`:
     ```sh
     lftp -u ftpuser,pass 192.168.1.2
     ```

     Alternatively, you can use the `ftptest` alias, which has been set up for convenience:
     ```sh
     ftptest
     ```

   - **Transfer Files**:
     Once connected to the FTP server, you can use FTP commands within the `victim2` shell to upload or download files to/from `victim1`. For example:
     ```sh
     put <file_name>   # Upload a file to victim1's FTP server
     get <file_name>   # Download a file from victim1's FTP server
     ```
     You have a `test.txt` file to try with:
     ```sh
     lftp ftpuser@192.168.1.2:~> put test.txt
     16 bytes transferred
     ```
   As files are exchanged, Inquisitor will capture and display the names of these files.

6. **View Logs:**
   Monitor the logs of each container to observe the attack's effects:
   ```sh
   make logs
   ```

7. **Stop and Clean Up the Docker Environment:**
   After testing, stop and remove the Docker containers:
   ```sh
   make stop
   make clean
   ```

   To completely remove all containers and start fresh:
   ```sh
   make fclean
   ```

### Makefile Targets Summary

- **`make all`**: Builds and starts the Docker containers.
- **`make logs`**: Displays logs from the attacker and victim containers.
- **`make stop`**: Stops the running Docker containers.
- **`make clean`**: Stops and removes the Docker containers.
- **`make fclean`**: Performs a full clean, including stopping and removing containers.
- **`make attacker`**: Opens a shell in the attacker container.
- **`make victim1`**: Opens a shell in the victim1 container.
- **`make victim2`**: Opens a shell in the victim2 container.

     
