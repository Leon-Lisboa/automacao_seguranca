import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import socket
import pandas as pd
import smtplib
import shutil
import os
from scapy.all import *

def scan_ports(host):
    open_ports = []
    for port in range(20, 1025):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((host, port)) == 0:
            open_ports.append(port)
        s.close()
    return open_ports

def analyze_logs(file_path):
    try:
        df = pd.read_csv(file_path)
        suspicious = df[df['Tipo'].str.contains("ERROR|WARNING")]  # Filtra erros e alertas
        return suspicious
    except Exception as e:
        return f"Erro ao analisar logs: {str(e)}"

def backup_files(source_dir, dest_dir):
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
    for file in os.listdir(source_dir):
        full_file_path = os.path.join(source_dir, file)
        if os.path.isfile(full_file_path):
            shutil.copy(full_file_path, dest_dir)

def send_alert_email(to_email, message):
    from_email = "seu_email@gmail.com"
    password = "sua_senha"
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, message)
        server.quit()
    except Exception as e:
        messagebox.showerror("Erro", f"Falha ao enviar email: {str(e)}")

class SecurityAutomationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Automação de Segurança")
        self.root.geometry("600x400")
        
        frame = tk.Frame(self.root)
        frame.pack(pady=10)
        
        btn_scan_ports = tk.Button(frame, text="Verificar Portas", command=self.run_port_scan)
        btn_scan_ports.pack(side=tk.LEFT, padx=5)
        
        btn_analyze_logs = tk.Button(frame, text="Analisar Logs", command=self.run_log_analysis)
        btn_analyze_logs.pack(side=tk.LEFT, padx=5)
        
        btn_backup = tk.Button(frame, text="Backup de Arquivos", command=self.run_backup)
        btn_backup.pack(side=tk.LEFT, padx=5)
        
        btn_send_email = tk.Button(frame, text="Enviar Alerta", command=self.run_email_alert)
        btn_send_email.pack(side=tk.LEFT, padx=5)
        
        self.log_output = tk.Text(self.root, height=10, width=70)
        self.log_output.pack(pady=10)
    
    def run_port_scan(self):
        host = tk.simpledialog.askstring("Entrada", "Digite o IP para escanear:")
        if host:
            open_ports = scan_ports(host)
            self.log_output.insert(tk.END, f"Portas abertas em {host}: {open_ports}\n")
    
    def run_log_analysis(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            results = analyze_logs(file_path)
            self.log_output.insert(tk.END, f"Análise de Logs:\n{results}\n")
    
    def run_backup(self):
        source_dir = filedialog.askdirectory(title="Selecionar Diretório de Origem")
        dest_dir = filedialog.askdirectory(title="Selecionar Diretório de Destino")
        if source_dir and dest_dir:
            backup_files(source_dir, dest_dir)
            self.log_output.insert(tk.END, "Backup realizado com sucesso!\n")
    
    def run_email_alert(self):
        to_email = tk.simpledialog.askstring("Entrada", "Digite o e-mail para alerta:")
        message = tk.simpledialog.askstring("Entrada", "Digite a mensagem do alerta:")
        if to_email and message:
            send_alert_email(to_email, message)
            self.log_output.insert(tk.END, "Alerta enviado com sucesso!\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityAutomationApp(root)
    root.mainloop()
