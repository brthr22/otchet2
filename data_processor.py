"""
Модуль для обработки и структурирования данных, полученных от парсера RedCheck.

Класс DataProcessor преобразует сырые данные в формат, готовый для генерации
таблиц отчета (Протокола анализа защищенности) по требованиям ФСТЭК.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict
from itertools import groupby


class DataProcessor:
    """
    Процессор данных для подготовки отчетов по методике ФСТЭК.

    Принимает словарь со списками хостов, уязвимостей, ПО и портов,
    и предоставляет методы для формирования конкретных таблиц отчета.
    """

    # Порядок сортировки уровней риска (от наиболее критичного к наименее)
    RISK_ORDER = {
        'Критический': 0,
        'Высокий': 1,
        'Средний': 2,
        'Низкий': 3,
        'Info': 4,
        'Неизвестный': 5  # Для случаев, когда риск не определен
    }

    # Ключевые слова для определения роли узла (Сервер или АРМ)
    SERVER_OS_KEYWORDS = [
        'server', 'сервер', 'astra linux server', 'red os server',
        'windows server', 'ubuntu server', 'debian server', 'centos',
        'rhel', 'red hat enterprise linux', 'suse', 'oracle linux',
        'freebsd', 'openbsd', 'netbsd', 'solaris', 'aix', 'hp-ux'
    ]

    def __init__(self, raw_data: Dict[str, List[Dict[str, Any]]]):
        """
        Инициализирует процессор данными от парсера.

        Args:
            raw_data: Словарь со списками 'hosts', 'vulnerabilities', 'software', 'ports'.
        """
        self.raw_data = raw_data
        self.hosts = raw_data.get('hosts', [])
        self.vulnerabilities = raw_data.get('vulnerabilities', [])
        self.software = raw_data.get('software', [])
        self.ports = raw_data.get('ports', [])

        # Создаем словарь хостов для быстрого поиска по IP
        self.hosts_by_ip: Dict[str, Dict[str, Any]] = {
            host['ip']: host for host in self.hosts if 'ip' in host
        }

    def _determine_node_role(self, os_name: str) -> str:
        """
        Определяет роль узла (Сервер или АРМ) на основе названия ОС.

        Args:
            os_name: Название операционной системы.

        Returns:
            Строка 'Сервер' или 'АРМ'.
        """
        if not os_name:
            return 'АРМ'  # По умолчанию считаем АРМ, если ОС неизвестна

        os_lower = os_name.lower()
        for keyword in self.SERVER_OS_KEYWORDS:
            if keyword in os_lower:
                return 'Сервер'
        return 'АРМ'

    def get_inventory_table(self) -> List[Dict[str, Any]]:
        """
        Формирует список словарей для таблицы инвентаризации.

        Каждая запись содержит: IP, hostname, ОС, роль (Сервер/АРМ).

        Returns:
            Список словарей с данными для таблицы инвентаризации.
        """
        inventory = []
        for host in self.hosts:
            ip = host.get('ip', '')
            hostname = host.get('hostname', '')
            os_info = host.get('os', '')
            role = self._determine_node_role(os_info)

            inventory.append({
                'ip': ip,
                'hostname': hostname,
                'os': os_info,
                'role': role
            })

        # Сортируем по IP для удобства чтения (опционально)
        # Используем простую сортировку строк, так как IP могут быть в разном формате
        inventory.sort(key=lambda x: x['ip'])
        return inventory

    def get_vuln_table(self) -> List[Dict[str, Any]]:
        """
        Формирует список уязвимостей для таблицы отчета.

        - Сортирует по уровню риска (Критический -> Высокий -> Средний -> Низкий -> Info).
        - Удаляет полные дубликаты (одинаковые IP, CVE, название, риск).

        Returns:
            Отсортированный список словарей с данными об уязвимостях.
        """
        # Удаление дубликатов
        seen = set()
        unique_vulns = []
        for vuln in self.vulnerabilities:
            # Создаем ключ для проверки на дубликат
            key = (
                vuln.get('ip', ''),
                vuln.get('cve', ''),
                vuln.get('name', ''),
                vuln.get('risk_level', '')
            )
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)

        # Сортировка по уровню риска
        def risk_sort_key(vuln: Dict[str, Any]) -> int:
            risk = vuln.get('risk_level', 'Неизвестный')
            return self.RISK_ORDER.get(risk, self.RISK_ORDER['Неизвестный'])

        sorted_vulns = sorted(unique_vulns, key=risk_sort_key)

        # Формируем финальный список, добавляя информацию о хосте (опционально)
        result_table = []
        for vuln in sorted_vulns:
            ip = vuln.get('ip', '')
            host_info = self.hosts_by_ip.get(ip, {})
            hostname = host_info.get('hostname', '')
            os_info = host_info.get('os', '')

            result_table.append({
                'ip': ip,
                'hostname': hostname,
                'os': os_info,
                'cve': vuln.get('cve', ''),
                'name': vuln.get('name', ''),
                'risk_level': vuln.get('risk_level', 'Неизвестный'),
                'cvss': vuln.get('cvss', ''),
                'product': vuln.get('product', ''),
                'recommendation': vuln.get('recommendation', '')
            })

        return result_table

    def get_software_table(self) -> List[Dict[str, Any]]:
        """
        Группирует программное обеспечение.

        В одной строке таблицы отображается: название ПО, версия и
        отсортированный список IP-адресов, где установлено данное ПО
        с данной версией.

        Returns:
            Список словарей с агрегированными данными о ПО.
        """
        # Группировка по (название, версия)
        # Используем словарь для накопления IP-адресов
        sw_groups: Dict[tuple, List[str]] = defaultdict(list)

        for sw_item in self.software:
            name = sw_item.get('name', 'Неизвестное ПО')
            version = sw_item.get('version', '')
            ip = sw_item.get('ip', '')

            if not ip:
                continue  # Пропускаем записи без IP

            key = (name, version)
            if ip not in sw_groups[key]:  # Избегаем дублирования IP внутри группы
                sw_groups[key].append(ip)

        # Формируем результирующий список
        result_table = []
        for (name, version), ips in sw_groups.items():
            # Сортируем IP-адреса для единообразия
            sorted_ips = sorted(ips)
            # Формируем строку со списком IP (через запятую или перенос строки)
            ips_str = ', '.join(sorted_ips)

            result_table.append({
                'name': name,
                'version': version,
                'ips': sorted_ips,       # Список для программной обработки
                'ips_display': ips_str   # Строка для отображения в таблице
            })

        # Сортируем результат по названию ПО, затем по версии
        result_table.sort(key=lambda x: (x['name'].lower(), x['version']))

        return result_table


if __name__ == '__main__':
    # Пример использования
    # Допустим, это данные, полученные от RedCheckXMLParser
    sample_raw_data = {
        'hosts': [
            {'ip': '192.168.1.10', 'hostname': 'WS-01', 'os': 'Windows 10 Pro'},
            {'ip': '192.168.1.20', 'hostname': 'SRV-DB', 'os': 'Ubuntu Server 20.04'},
            {'ip': '192.168.1.30', 'hostname': 'SRV-WEB', 'os': 'Astra Linux Server'},
            {'ip': '192.168.1.40', 'hostname': 'WS-02', 'os': 'Windows 11'},
        ],
        'vulnerabilities': [
            {'ip': '192.168.1.10', 'cve': 'CVE-2023-0001', 'name': 'Vuln A', 'risk_level': 'Высокий', 'cvss': '7.5', 'product': 'Browser', 'recommendation': 'Update'},
            {'ip': '192.168.1.20', 'cve': 'CVE-2023-0002', 'name': 'Vuln B', 'risk_level': 'Критический', 'cvss': '9.8', 'product': 'DB Engine', 'recommendation': 'Patch immediately'},
            {'ip': '192.168.1.10', 'cve': 'CVE-2023-0001', 'name': 'Vuln A', 'risk_level': 'Высокий', 'cvss': '7.5', 'product': 'Browser', 'recommendation': 'Update'}, # Дубликат
            {'ip': '192.168.1.30', 'cve': 'CVE-2023-0003', 'name': 'Vuln C', 'risk_level': 'Средний', 'cvss': '5.0', 'product': 'Web Server', 'recommendation': 'Configure'},
            {'ip': '192.168.1.40', 'cve': 'CVE-2023-0004', 'name': 'Vuln D', 'risk_level': 'Низкий', 'cvss': '2.1', 'product': 'OS Component', 'recommendation': 'Monitor'},
            {'ip': '192.168.1.20', 'cve': 'CVE-2023-0005', 'name': 'Vuln E', 'risk_level': 'Высокий', 'cvss': '8.1', 'product': 'DB Tool', 'recommendation': 'Update'},
        ],
        'software': [
            {'ip': '192.168.1.10', 'name': 'Firefox', 'version': '102.0'},
            {'ip': '192.168.1.40', 'name': 'Firefox', 'version': '102.0'},
            {'ip': '192.168.1.20', 'name': 'PostgreSQL', 'version': '13.4'},
            {'ip': '192.168.1.30', 'name': 'Nginx', 'version': '1.18.0'},
            {'ip': '192.168.1.10', 'name': '7-Zip', 'version': '19.00'},
        ],
        'ports': [] # Порты не используются в этих методах, но могут быть в raw_data
    }

    processor = DataProcessor(sample_raw_data)

    print("--- Таблица инвентаризации ---")
    inv_table = processor.get_inventory_table()
    for row in inv_table:
        print(f"{row['ip']}\t{row['hostname']}\t{row['os']}\t{row['role']}")

    print("\n--- Таблица уязвимостей (отсортирована по риску, без дублей) ---")
    vuln_table = processor.get_vuln_table()
    for row in vuln_table:
        print(f"{row['risk_level']}\t{row['ip']}\t{row['cve']}\t{row['name']}")

    print("\n--- Таблица программного обеспечения (сгруппировано) ---")
    sw_table = processor.get_software_table()
    for row in sw_table:
        print(f"{row['name']}\t{row['version']}\t{row['ips_display']}")
