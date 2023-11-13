Привет, я сделал собственный maxpatrol!

Что нам необходимо сделать, чтобы все работало корректно:
1. Создайте базу данных под названием scan_ssh
2. Далее создайте новую таблицу ниже можете скопировать
CREATE TABLE IF NOT EXISTS scan_results (
    id SERIAL PRIMARY KEY,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    host VARCHAR(255),
    command TEXT,
    os_info TEXT,
    ports TEXT
);

Далее необходимо запустить .py файл и наслаждаться, инструкция по настройке kali и установке на linux под постом. 
