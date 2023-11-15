import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QPlainTextEdit, QLineEdit
from PyQt5.uic import loadUi
import subprocess 
from functools import partial
import paramiko
import logging
import psycopg2
from psycopg2 import sql

log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ssh_log.txt')
logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(message)s', filemode='w')
logging.getLogger('paramiko').setLevel(logging.ERROR)

class MaxPatrolApp(QMainWindow):
    def __init__(self):
        super(MaxPatrolApp, self).__init__()
        ui_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'maxpatrol.ui')
        loadUi(ui_file_path, self)

        self.dport_input.setText("5432")
        self.port_input.setText("22")

        self.pass_input = self.findChild(QLineEdit, 'pass_input')
        self.dpass_input = self.findChild(QLineEdit, 'dpass_input')
        
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.dpass_input.setEchoMode(QLineEdit.Password)

        self.output_button.clicked.connect(self.connect_to_ssh)
        self.scan_button.clicked.connect(self.scan_network)
        self.inf_output = self.findChild(QPlainTextEdit, 'inf_output')
        self.scan_output = self.findChild(QPlainTextEdit, 'scan_output')
        self.clear_button.clicked.connect(self.clear_gui)

    def clear_gui(self):
        self.inf_output.clear()
        self.scan_output.clear()
        self.ip_input.clear()
        self.login_input.clear()
        self.pass_input.clear()
        self.dbname_input.clear()
        self.user_input.clear()
        self.dpass_input.clear()
        self.dhost_input.clear()
        

    def connect_to_ssh(self):
        host = self.ip_input.text()
        port = int(self.port_input.text())
        username = self.login_input.text()
        password = self.pass_input.text()

        db_parametrs = {
            'dbname': self.dbname_input.text(),
            'user': self.user_input.text(),
            'password': self.dpass_input.text(),
            'host': self.dhost_input.text(),
            'port': self.dport_input.text(),
        }

        ssh_connection(host, port, username, password, db_parametrs)

        self.inf_output.clear()

        self.execute_and_set_text("Information OS:", "uname -a", host, port, username, password)
        self.execute_and_set_text("Distribution:", "lsb_release -d", host, port, username, password)
        self.execute_and_set_text("Arch:", "uname -m", host, port, username, password)
        ip_address = self.ip_input.text()
        self.execute_and_set_text("Ports:", "nmap -p- {0} | grep 'open'".format(ip_address), host, port, username, password)
        self.execute_and_set_text("Disks:", "df -h", host, port, username, password)
        self.execute_and_set_text("USB:", "lsusb", host, port, username, password)

    def execute_and_set_text(self, label, command, host, port, username, password):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=username, password=password)
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode()

            self.inf_output.setPlainText(f"{self.inf_output.toPlainText()}\n{label}\n{output}")

        except Exception as e:
            self.inf_output.setPlainText(f"{self.inf_output.toPlainText()}\n{label}\nError: {str(e)}")

        finally:
            client.close()

    def scan_network(self):
        host = self.ip_input.text()
        port = int(self.port_input.text())
        username = self.login_input.text()
        password = self.pass_input.text()

        self.scan_output.clear()
        self.execute_in_scan("Local Net:", "arp -n | awk '{print $1, $3}'", host, port, username, password)

    
    def execute_in_scan(self, label, command, host, port, username, password):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=username, password=password)
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode()

            self.scan_output.setPlainText(f"{self.scan_output.toPlainText()}\n{label}\n{output}")

        except Exception as e:
            self.scan_output.setPlainText(f"{self.inf_output.toPlainText()}\n{label}\nError: {str(e)}")

        finally:
            client.close()

def ssh_connection(host, port, username, password, db_parametrs):
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=username, password=password)

        logging.info(f"Успешное подключение по SSH к {host}")

        execute_and_write_to_postgres(client, host, "uname -a", "os_info", db_parametrs)
        execute_and_write_to_postgres(client, host, f"nmap -p- {host} | grep 'open'", "ports", db_parametrs)

        log_result(True, "Operation completed successfully.")
    except Exception as e:
        log_result(False, f"Operation failed. Error: {str(e)}")
    finally:
        client.close()

def execute_and_write_to_postgres(client, host, command, column, db_parametrs):
    try:
        stdin, stdout, stderr = client.exec_command(command)
        command_output = stdout.read().decode()
        logging.info(f"Выполнена команда '{command}'")

        write_to_postgres(host, command, command_output, column, db_parametrs)

        log_result(True, "Operation completed successfully.")
    except Exception as e:
        log_result(False, f"Operation failed. Error: {str(e)}")

def write_to_postgres(host, command, output, column, db_parametrs):
    try:
        conn = psycopg2.connect(**db_parametrs)
        cursor = conn.cursor()

        insert_query = sql.SQL("INSERT INTO scan_results (host, command, {}, date) VALUES (%s, %s, %s, CURRENT_TIMESTAMP)").format(sql.Identifier(column))
        cursor.execute(insert_query, (host, command, output))

        conn.commit()
        log_result(True, "Write to DataBase completed successfully.")
    except Exception as e:
        log_result(False, f"Write to DataBase failed. Error: {str(e)}")
    finally:
        cursor.close()
        conn.close()

def log_result(success, message):
    log_entry = f"{'Success' if success else 'Error'}: {message}"
    logging.info(log_entry)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MaxPatrolApp()
    window.show()
    sys.exit(app.exec_())
