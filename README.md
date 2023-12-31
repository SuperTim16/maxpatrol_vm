Привет, я сделал собственный maxpatrol!

**[+] Что нам необходимо сделать, чтобы все работало корректно:**
1. Создайте базу данных под названием scan_ssh
   CREATE DATABASE your_database_name;
3. Далее создайте новую таблицу scan_results ниже можете скопировать
    CREATE TABLE IF NOT EXISTS scan_results (
        id SERIAL PRIMARY KEY,
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        host VARCHAR(255),
        command TEXT,
        os_info TEXT,
        ports TEXT
    );

**[+] Что может мой Maxpatrol:**
1. Подключение по протоколу ssh (необходимо указать host к которому подключаетесь, порт, имя, пароль)
2. Подключение к postresql (необходимо написать имя(в нашем случае scan_ssh), имя(для подключения), пароль(для подключения), host(где стоит база данных), порт)
3. Записывает логи в файл ssh_log
4. Сканирование ОС к которой идет подключение через ssh (Информация об ОС, дистрибутив, архитектура, открые порты, диски, USB-порты)
5. Сканирование локальной сети (На данный момент сканирование локальной сети возможно, только при подключении по ssh к Linux ОС. В будущем это исправлю и можно будет сканировать локальную сеть без подключения)
6. Запись данных в базу данных (Хост, выполненые команды, информацию об ОС, открытые порты)

**[+] Как просмотреть Базу Данных:**
1. Нам потребуется SQL Shell
2. Заходим вводя свой логин и пароль
3. Создаем базу данных
4. Вводим:
   \c scan_ssh
5. Создаем таблицу
6. Просматриваем базу данных после выполнения программы
   SELECT * FROM scan_results;

**[+] Установка**

Для Windows
   - Скачайте 2 файла с GitHub и переместите их в 1 папку
   - Зайдите в редактор кода, например Visual Studio Code
   - В терминали необходимо будет установить библиотеки для корректной работы
   - `pip install PyQt5`
   - `pip install paramiko`
   - `pip install logging`
   - `pip install psycopg2`
   - Чтобы запустить файл из cmd
   - `cd Путь\\к\\файлу`
   - `python maxpatrol.py`

Для Debian (Ubuntu, Kali-Linux)
   - `sudo apt update && upgrade`
   - `sudo apt install git python3 python3-pip`
   - `sudo pip3 install PyQt5`

Для Arch (Manjaro)
   - `sudo pacman -S git python3 python-pip`

Клонируй репозиторий
   - `git clone https://github.com/SuperTim16/maxpatrol_vm`

Войди в директорию
   - `cd maxpatrol_vm`

Запуск
   - `python3 ssh_connection_sc.py`

