import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
import paramiko
import os
import json

# Expanded script library, grouped by category
SCRIPTS = {
    # --- Windows Scripts ---
    "Windows: Disable Guest Account": {
        "script": "net user guest /active:no",
        "notes": "Disables the built-in Guest account for better security."
    },
    "Windows: Enable Windows Firewall": {
        "script": "netsh advfirewall set allprofiles state on",
        "notes": "Enables Windows Firewall for all profiles."
    },
    "Windows: Disable SMBv1": {
        "script": "Set-SmbServerConfiguration -EnableSMB1Protocol $false",
        "notes": "Disables the insecure SMBv1 protocol."
    },
    "Windows: Set Account Lockout Policy": {
        "script": "net accounts /lockoutthreshold:5",
        "notes": "Locks out accounts after 5 failed login attempts."
    },
    "Windows: Enable BitLocker": {
        "script": "manage-bde -on C:",
        "notes": "Enables BitLocker encryption on the C: drive."
    },
    "Windows: Disable Autorun": {
        "script": r'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f',
        "notes": "Disables Autorun for all drives."
    },
    "Windows: Enable Windows Updates": {
        "script": "sc config wuauserv start= auto & net start wuauserv",
        "notes": "Ensures Windows Update service is running."
    },
    "Windows: Audit Local Admins": {
        "script": "net localgroup administrators",
        "notes": "Lists all local administrators."
    },
    # --- Linux Scripts ---
    "Linux: Enable Firewall": {
        "script": "sudo ufw enable",
        "notes": "Enables UFW firewall on Ubuntu/Debian systems."
    },
    "Linux: Set Password Policy": {
        "script": "sudo chage --maxdays 90 {username}",
        "notes": "Sets password expiration to 90 days for a user."
    },
    "Linux: Audit Sudoers": {
        "script": "sudo cat /etc/sudoers",
        "notes": "Displays the sudoers file for auditing."
    },
    "Linux: Disable Root SSH Login": {
        "script": "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
        "notes": "Prevents root from logging in via SSH."
    },
    "Linux: Set SSH Idle Timeout": {
        "script": "echo 'ClientAliveInterval 300\nClientAliveCountMax 0' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart sshd",
        "notes": "Disconnects idle SSH sessions after 5 minutes."
    },
    "Linux: Disable Unused Filesystems": {
        "script": "echo 'install cramfs /bin/true' | sudo tee -a /etc/modprobe.d/cramfs.conf",
        "notes": "Disables the cramfs filesystem module."
    },
    "Linux: Remove Unused Packages": {
        "script": "sudo apt-get autoremove -y",
        "notes": "Removes unused packages to reduce attack surface."
    },
    "Linux: Enable SELinux": {
        "script": "sudo setenforce 1",
        "notes": "Enables SELinux in enforcing mode."
    },
    "Linux: Check World-Writable Files": {
        "script": "find / -xdev -type f -perm -0002 -ls",
        "notes": "Finds all world-writable files."
    },
    "Linux: List Listening Ports": {
        "script": "sudo netstat -tulpn",
        "notes": "Lists all listening ports and associated services."
    },
    "Linux: Check for Empty Passwords": {
        "script": "sudo awk -F: '($2==\"\" ) { print $1 }' /etc/shadow",
        "notes": "Lists users with empty passwords."
    },
    "Linux: Disable IPv6": {
        "script": "echo 'net.ipv6.conf.all.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p",
        "notes": "Disables IPv6 networking."
    },
    "Linux: Restrict Cron Access": {
        "script": "echo 'root' | sudo tee /etc/cron.allow",
        "notes": "Restricts cron usage to root only."
    },
    "Linux: Check for SUID/SGID Files": {
        "script": "find / -perm /6000 -type f -exec ls -ld {} \\;",
        "notes": "Finds all files with SUID or SGID permissions."
    },
    # --- Cloud/General Scripts ---
    "AWS: List S3 Buckets": {
        "script": "aws s3 ls",
        "notes": "Lists all S3 buckets in your AWS account."
    },
    "AWS: Check Public Buckets": {
        "script": "aws s3api list-buckets --query 'Buckets[].Name' --output text | xargs -n1 -I{} aws s3api get-bucket-acl --bucket {}",
        "notes": "Checks ACLs for all S3 buckets."
    },
    "Azure: List VMs": {
        "script": "az vm list -o table",
        "notes": "Lists all Azure virtual machines."
    },
    "GCP: List Compute Instances": {
        "script": "gcloud compute instances list",
        "notes": "Lists all Google Cloud compute instances."
    }
}

def load_scripts():
    try:
        with open("scripts.json", "r") as f:
            return json.load(f)
    except Exception:
        return SCRIPTS  # fallback to built-in

SCRIPTS = load_scripts()

class SecurityConfigApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Security Configuration Compiler")
        self.geometry("700x600")
        menubar = tk.Menu(self)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Usage Guide", command=self.show_help)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)
        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="Search Scripts:").pack(pady=5)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.update_dropdown)
        search_entry = ttk.Entry(self, textvariable=self.search_var)
        search_entry.pack(fill='x', padx=10)

        ttk.Label(self, text="Select Security Script:").pack(pady=5)
        self.script_var = tk.StringVar()
        self.dropdown = ttk.Combobox(self, textvariable=self.script_var, state="readonly")
        self.dropdown['values'] = list(SCRIPTS.keys())
        self.dropdown.pack(fill='x', padx=10)
        self.dropdown.bind("<<ComboboxSelected>>", self.show_script_details)

        ttk.Label(self, text="Script:").pack(pady=5)
        self.script_text = scrolledtext.ScrolledText(self, height=4)
        self.script_text.pack(fill='x', padx=10)

        ttk.Label(self, text="Notes:").pack(pady=5)
        self.notes_text = scrolledtext.ScrolledText(self, height=4)
        self.notes_text.pack(fill='x', padx=10)

        ttk.Button(self, text="Add to Compilation", command=self.add_to_compilation).pack(pady=5)
        ttk.Button(self, text="Save Compilation", command=self.save_compilation).pack(pady=5)
        ttk.Button(self, text="Upload to Remote", command=self.upload_to_remote).pack(pady=5)
        ttk.Button(self, text="Generate Report", command=self.generate_report).pack(pady=5)
        ttk.Button(self, text="Schedule Script", command=self.schedule_script).pack(pady=5)

        ttk.Label(self, text="Compiled Scripts:").pack(pady=5)
        self.compilation_text = scrolledtext.ScrolledText(self, height=10)
        self.compilation_text.pack(fill='both', padx=10, expand=True)

    def update_dropdown(self, *args):
        search = self.search_var.get().lower()
        filtered = [k for k in SCRIPTS if search in k.lower()]
        self.dropdown['values'] = filtered

    def show_script_details(self, event):
        key = self.script_var.get()
        self.script_text.delete('1.0', tk.END)
        self.notes_text.delete('1.0', tk.END)
        if key in SCRIPTS:
            script = SCRIPTS[key]['script']
            # Parameter replacement for {username} and others
            params = [p for p in ["{username}", "{bucket}", "{path}"] if p in script]
            for param in params:
                value = simpledialog.askstring("Parameter", f"Enter value for {param}:")
                script = script.replace(param, value or param)
            self.script_text.insert(tk.END, script)
            self.notes_text.insert(tk.END, SCRIPTS[key]['notes'])

    def add_to_compilation(self):
        script = self.script_text.get('1.0', tk.END).strip()
        notes = self.notes_text.get('1.0', tk.END).strip()
        if script:
            self.compilation_text.insert(tk.END, f"# Notes: {notes}\n{script}\n\n")
        else:
            messagebox.showwarning("Warning", "No script to add.")

    def save_compilation(self):
        content = self.compilation_text.get('1.0', tk.END)
        if not content.strip():
            messagebox.showwarning("Warning", "No scripts to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".sh", filetypes=[("Shell Script", "*.sh"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write(content)
            messagebox.showinfo("Saved", f"Compilation saved to {file_path}")

    def upload_to_remote(self):
        content = self.compilation_text.get('1.0', tk.END)
        if not content.strip():
            messagebox.showwarning("Warning", "No scripts to upload.")
            return
        upload_win = tk.Toplevel(self)
        upload_win.title("Upload to Remote")
        ttk.Label(upload_win, text="Hostname:").grid(row=0, column=0)
        ttk.Label(upload_win, text="Username:").grid(row=1, column=0)
        ttk.Label(upload_win, text="Password:").grid(row=2, column=0)
        ttk.Label(upload_win, text="Remote Path:").grid(row=3, column=0)
        host_entry = ttk.Entry(upload_win)
        user_entry = ttk.Entry(upload_win)
        pass_entry = ttk.Entry(upload_win, show="*")
        path_entry = ttk.Entry(upload_win)
        host_entry.grid(row=0, column=1)
        user_entry.grid(row=1, column=1)
        pass_entry.grid(row=2, column=1)
        path_entry.grid(row=3, column=1)
        def do_upload():
            hostname = host_entry.get()
            username = user_entry.get()
            password = pass_entry.get()
            remote_path = path_entry.get()
            if not all([hostname, username, password, remote_path]):
                messagebox.showwarning("Warning", "All fields required.")
                return
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname, username=username, password=password)
                sftp = ssh.open_sftp()
                local_temp = "temp_script.sh"
                with open(local_temp, 'w') as f:
                    f.write(content)
                sftp.put(local_temp, remote_path)
                sftp.close()
                ssh.close()
                os.remove(local_temp)
                messagebox.showinfo("Success", f"Uploaded to {hostname}:{remote_path}")
                upload_win.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e))
        ttk.Button(upload_win, text="Upload", command=do_upload).grid(row=4, column=0, columnspan=2, pady=5)

    def generate_report(self):
        content = self.compilation_text.get('1.0', tk.END)
        if not content.strip():
            messagebox.showwarning("Warning", "No scripts to report.")
            return
        report = "Security Hardening Report\n\n"
        for line in content.splitlines():
            if line.startswith("# Notes:"):
                report += line + "\n"
        report_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt")])
        if report_path:
            with open(report_path, 'w') as f:
                f.write(report)
            messagebox.showinfo("Report Saved", f"Report saved to {report_path}")

    def schedule_script(self):
        messagebox.showinfo("Schedule", "Scheduling feature coming soon! (Integrate with Task Scheduler or cron)")

    def show_help(self):
        messagebox.showinfo(
            "Help",
            "1. Search or select a script from the dropdown.\n"
            "2. Edit the script or notes if needed.\n"
            "3. Add to compilation.\n"
            "4. Save, upload, or generate a report.\n"
            "5. Scheduling and advanced features coming soon.\n"
            "For more, see the documentation or contact support."
        )

if __name__ == "__main__":
    app = SecurityConfigApp()
    app.mainloop()