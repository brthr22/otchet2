"""
Модуль для парсинга выгрузок сканера RedCheck в формате XML.

Этот модуль предоставляет класс `RedCheckXMLParser`, который извлекает информацию
о хостах, уязвимостях, программном обеспечении и открытых портах из XML-файлов,
сгенерированных сканером безопасности RedCheck.

Пример использования:
    parser = RedCheckXMLParser()
    result = parser.parse_file("scan_result.xml")
    
    print(f"Найдено хостов: {len(result['hosts'])}")
    print(f"Найдено уязвимостей: {len(result['vulnerabilities'])}")
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from pathlib import Path


class RedCheckXMLParser:
    """
    Парсер для обработки результатов сканирования сканера уязвимостей RedCheck.
    
    Атрибуты:
        TAG_CONFIG (Dict): Конфигурация имен тегов для поиска в XML.
                          Может быть изменена при необходимости адаптации 
                          к разным версиям формата выгрузки.
    """
    
    # Конфигурация тегов - легко модифицировать под изменения структуры XML
    TAG_CONFIG = {
        # Корневые элементы секций
        'root': 'ScanResult',
        'hosts_section': 'Hosts',
        'vulns_section': 'Vulnerabilities',
        'software_section': 'Software',
        'ports_section': 'Ports',
        
        # Элементы хоста
        'host': 'Host',
        'host_ip': 'IPAddress',
        'host_name': 'Hostname',
        'host_os': 'OS',
        
        # Элементы уязвимости
        'vulnerability': 'Vulnerability',
        'vuln_host_ip': 'HostIP',  # Привязка к хосту
        'vuln_cve': 'CVE',
        'vuln_name': 'Name',
        'vuln_risk': 'RiskLevel',
        'vuln_cvss': 'CVSS',
        'vuln_product': 'AffectedProduct',
        'vuln_recommendation': 'Recommendation',
        
        # Элементы ПО
        'software_item': 'SoftwareItem',
        'sw_host_ip': 'HostIP',  # Привязка к хосту
        'sw_name': 'ProductName',
        'sw_version': 'Version',
        
        # Элементы портов
        'port_item': 'Port',
        'port_host_ip': 'HostIP',  # Привязка к хосту
        'port_number': 'Number',
        'port_protocol': 'Protocol',
        'port_service': 'Service',
    }
    
    # Маппинг уровней риска (если в файле числовые значения)
    RISK_LEVEL_MAP = {
        '0': 'Низкий',
        '1': 'Средний',
        '2': 'Высокий',
        '3': 'Критический',
        'critical': 'Критический',
        'high': 'Высокий',
        'medium': 'Средний',
        'low': 'Низкий',
        'критический': 'Критический',
        'высокий': 'Высокий',
        'средний': 'Средний',
        'низкий': 'Низкий',
    }

    def __init__(self):
        """Инициализация парсера."""
        self.tree: Optional[ET.ElementTree] = None
        self.root: Optional[ET.Element] = None

    def _safe_get_text(self, parent: ET.Element, tag: str, default: str = "") -> str:
        """
        Безопасное получение текста из дочернего элемента.
        
        Если элемент не найден или текст отсутствует, возвращает значение по умолчанию.
        
        Args:
            parent: Родительский элемент для поиска.
            tag: Имя тега для поиска.
            default: Значение по умолчанию, если элемент не найден.
            
        Returns:
            Текст содержимого элемента или значение по умолчанию.
        """
        try:
            child = parent.find(tag)
            if child is not None and child.text:
                return child.text.strip()
            return default
        except Exception:
            return default

    def _normalize_risk_level(self, risk_value: str) -> str:
        """
        Нормализация уровня риска к стандартным значениям.
        
        Преобразует различные форматы представления уровня риска 
        (числа, английские/русские названия) к единому формату.
        
        Args:
            risk_value: Исходное значение уровня риска.
            
        Returns:
            Нормализованное значение уровня риска.
        """
        if not risk_value:
            return "Не определен"
        
        risk_lower = risk_value.lower().strip()
        
        # Проверяем маппинг
        if risk_lower in self.RISK_LEVEL_MAP:
            return self.RISK_LEVEL_MAP[risk_lower]
        
        # Если значение уже в нужном формате
        if risk_value in ['Критический', 'Высокий', 'Средний', 'Низкий']:
            return risk_value
            
        return risk_value

    def _parse_hosts(self, hosts_section: ET.Element) -> List[Dict[str, str]]:
        """
        Парсинг информации о хостах.
        
        Args:
            hosts_section: Элемент секции хостов.
            
        Returns:
            Список словарей с информацией о хостах.
        """
        hosts = []
        tag_config = self.TAG_CONFIG
        
        try:
            host_elements = hosts_section.findall(tag_config['host'])
            
            for host_elem in host_elements:
                try:
                    host_data = {
                        'ip': self._safe_get_text(
                            host_elem, 
                            tag_config['host_ip'], 
                            default="unknown"
                        ),
                        'hostname': self._safe_get_text(
                            host_elem, 
                            tag_config['host_name']
                        ),
                        'os': self._safe_get_text(
                            host_elem, 
                            tag_config['host_os']
                        ),
                    }
                    
                    # Добавляем только если есть хотя бы IP
                    if host_data['ip'] != "unknown":
                        hosts.append(host_data)
                        
                except Exception as e:
                    # Пропускаем проблемные записи, логируем ошибку
                    print(f"Warning: Ошибка при парсинге хоста: {e}")
                    continue
                    
        except Exception as e:
            print(f"Warning: Ошибка при обработке секции хостов: {e}")
            
        return hosts

    def _parse_vulnerabilities(self, vulns_section: ET.Element) -> List[Dict[str, Any]]:
        """
        Парсинг информации об уязвимостях.
        
        Args:
            vulns_section: Элемент секции уязвимостей.
            
        Returns:
            Список словарей с информацией об уязвимостях.
        """
        vulnerabilities = []
        tag_config = self.TAG_CONFIG
        
        try:
            vuln_elements = vulns_section.findall(tag_config['vulnerability'])
            
            for vuln_elem in vuln_elements:
                try:
                    raw_risk = self._safe_get_text(
                        vuln_elem, 
                        tag_config['vuln_risk']
                    )
                    
                    vuln_data = {
                        'ip': self._safe_get_text(
                            vuln_elem, 
                            tag_config['vuln_host_ip'], 
                            default="unknown"
                        ),
                        'cve': self._safe_get_text(
                            vuln_elem, 
                            tag_config['vuln_cve']
                        ),
                        'name': self._safe_get_text(
                            vuln_elem, 
                            tag_config['vuln_name']
                        ),
                        'risk_level': self._normalize_risk_level(raw_risk),
                        'cvss': self._safe_get_text(
                            vuln_elem, 
                            tag_config['vuln_cvss']
                        ),
                        'product': self._safe_get_text(
                            vuln_elem, 
                            tag_config['vuln_product']
                        ),
                        'recommendation': self._safe_get_text(
                            vuln_elem, 
                            tag_config['vuln_recommendation']
                        ),
                    }
                    
                    # Добавляем только если есть привязка к хосту
                    if vuln_data['ip'] != "unknown":
                        vulnerabilities.append(vuln_data)
                        
                except Exception as e:
                    print(f"Warning: Ошибка при парсинге уязвимости: {e}")
                    continue
                    
        except Exception as e:
            print(f"Warning: Ошибка при обработке секции уязвимостей: {e}")
            
        return vulnerabilities

    def _parse_software(self, software_section: ET.Element) -> List[Dict[str, str]]:
        """
        Парсинг информации о программном обеспечении.
        
        Args:
            software_section: Элемент секции ПО.
            
        Returns:
            Список словарей с информацией о ПО.
        """
        software_list = []
        tag_config = self.TAG_CONFIG
        
        try:
            sw_elements = software_section.findall(tag_config['software_item'])
            
            for sw_elem in sw_elements:
                try:
                    sw_data = {
                        'ip': self._safe_get_text(
                            sw_elem, 
                            tag_config['sw_host_ip'], 
                            default="unknown"
                        ),
                        'name': self._safe_get_text(
                            sw_elem, 
                            tag_config['sw_name']
                        ),
                        'version': self._safe_get_text(
                            sw_elem, 
                            tag_config['sw_version']
                        ),
                    }
                    
                    # Добавляем только если есть привязка к хосту и название
                    if sw_data['ip'] != "unknown" and sw_data['name']:
                        software_list.append(sw_data)
                        
                except Exception as e:
                    print(f"Warning: Ошибка при парсинге ПО: {e}")
                    continue
                    
        except Exception as e:
            print(f"Warning: Ошибка при обработке секции ПО: {e}")
            
        return software_list

    def _parse_ports(self, ports_section: ET.Element) -> List[Dict[str, str]]:
        """
        Парсинг информации об открытых портах.
        
        Args:
            ports_section: Элемент секции портов.
            
        Returns:
            Список словарей с информацией о портах.
        """
        ports = []
        tag_config = self.TAG_CONFIG
        
        try:
            port_elements = ports_section.findall(tag_config['port_item'])
            
            for port_elem in port_elements:
                try:
                    port_data = {
                        'ip': self._safe_get_text(
                            port_elem, 
                            tag_config['port_host_ip'], 
                            default="unknown"
                        ),
                        'port': self._safe_get_text(
                            port_elem, 
                            tag_config['port_number']
                        ),
                        'protocol': self._safe_get_text(
                            port_elem, 
                            tag_config['port_protocol']
                        ),
                        'service': self._safe_get_text(
                            port_elem, 
                            tag_config['port_service']
                        ),
                    }
                    
                    # Добавляем только если есть привязка к хосту и номер порта
                    if port_data['ip'] != "unknown" and port_data['port']:
                        ports.append(port_data)
                        
                except Exception as e:
                    print(f"Warning: Ошибка при парсинге порта: {e}")
                    continue
                    
        except Exception as e:
            print(f"Warning: Ошибка при обработке секции портов: {e}")
            
        return ports

    def parse_file(self, file_path: str) -> Dict[str, List]:
        """
        Парсинг XML-файла с результатами сканирования.
        
        Основная точка входа для обработки файла. Извлекает все доступные
        данные и возвращает их в структурированном виде.
        
        Args:
            file_path: Путь к XML-файлу с результатами сканирования.
            
        Returns:
            Словарь со следующими ключами:
                - 'hosts': список хостов
                - 'vulnerabilities': список уязвимостей
                - 'software': список ПО
                - 'ports': список портов
                
        Raises:
            FileNotFoundError: Если файл не найден.
            ET.ParseError: Если файл не является корректным XML.
        """
        result = {
            'hosts': [],
            'vulnerabilities': [],
            'software': [],
            'ports': [],
        }
        
        tag_config = self.TAG_CONFIG
        
        try:
            # Проверка существования файла
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"Файл не найден: {file_path}")
            
            # Парсинг XML
            self.tree = ET.parse(str(path))
            self.root = self.tree.getroot()
            
            # Поиск кореневого элемента (с учетом возможного отсутствия точного совпадения)
            root_elem = self.root.find(tag_config['root'])
            if root_elem is None:
                # Если точного совпадения нет, используем корень файла
                root_elem = self.root
            
            # Парсинг секции хостов
            hosts_section = root_elem.find(tag_config['hosts_section'])
            if hosts_section is not None:
                result['hosts'] = self._parse_hosts(hosts_section)
            else:
                print(f"Info: Секция '{tag_config['hosts_section']}' не найдена")
            
            # Парсинг секции уязвимостей
            vulns_section = root_elem.find(tag_config['vulns_section'])
            if vulns_section is not None:
                result['vulnerabilities'] = self._parse_vulnerabilities(vulns_section)
            else:
                print(f"Info: Секция '{tag_config['vulns_section']}' не найдена")
            
            # Парсинг секции ПО
            software_section = root_elem.find(tag_config['software_section'])
            if software_section is not None:
                result['software'] = self._parse_software(software_section)
            else:
                print(f"Info: Секция '{tag_config['software_section']}' не найдена")
            
            # Парсинг секции портов
            ports_section = root_elem.find(tag_config['ports_section'])
            if ports_section is not None:
                result['ports'] = self._parse_ports(ports_section)
            else:
                print(f"Info: Секция '{tag_config['ports_section']}' не найдена")
            
            return result
            
        except FileNotFoundError:
            raise
        except ET.ParseError as e:
            raise ET.ParseError(f"Ошибка парсинга XML: {e}")
        except Exception as e:
            raise Exception(f"Неожиданная ошибка при парсинге файла: {e}")

    def parse_string(self, xml_string: str) -> Dict[str, List]:
        """
        Парсинг XML из строки.
        
        Полезно для тестирования или обработки данных, полученных иным способом.
        
        Args:
            xml_string: Строка с XML-данными.
            
        Returns:
            Словарь с результатами парсинга (см. parse_file).
        """
        result = {
            'hosts': [],
            'vulnerabilities': [],
            'software': [],
            'ports': [],
        }
        
        tag_config = self.TAG_CONFIG
        
        try:
            # Парсинг XML из строки
            self.root = ET.fromstring(xml_string)
            
            # Поиск кореневого элемента
            root_elem = self.root.find(tag_config['root'])
            if root_elem is None:
                root_elem = self.root
            
            # Парсинг всех секций
            hosts_section = root_elem.find(tag_config['hosts_section'])
            if hosts_section is not None:
                result['hosts'] = self._parse_hosts(hosts_section)
            
            vulns_section = root_elem.find(tag_config['vulns_section'])
            if vulns_section is not None:
                result['vulnerabilities'] = self._parse_vulnerabilities(vulns_section)
            
            software_section = root_elem.find(tag_config['software_section'])
            if software_section is not None:
                result['software'] = self._parse_software(software_section)
            
            ports_section = root_elem.find(tag_config['ports_section'])
            if ports_section is not None:
                result['ports'] = self._parse_ports(ports_section)
            
            return result
            
        except ET.ParseError as e:
            raise ET.ParseError(f"Ошибка парсинга XML строки: {e}")
        except Exception as e:
            raise Exception(f"Неожиданная ошибка при парсинге строки: {e}")


# Пример использования и тестирования
if __name__ == "__main__":
    # Пример XML для тестирования
    test_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <ScanResult>
        <Hosts>
            <Host>
                <IPAddress>192.168.1.10</IPAddress>
                <Hostname>server01.local</Hostname>
                <OS>Windows Server 2019</OS>
            </Host>
            <Host>
                <IPAddress>192.168.1.20</IPAddress>
                <Hostname>webserver.local</Hostname>
                <OS>Ubuntu 20.04 LTS</OS>
            </Host>
        </Hosts>
        <Vulnerabilities>
            <Vulnerability>
                <HostIP>192.168.1.10</HostIP>
                <CVE>CVE-2021-44228</CVE>
                <Name>Apache Log4j Remote Code Execution</Name>
                <RiskLevel>Critical</RiskLevel>
                <CVSS>10.0</CVSS>
                <AffectedProduct>Apache Log4j</AffectedProduct>
                <Recommendation>Update to Log4j 2.17.0 or later</Recommendation>
            </Vulnerability>
            <Vulnerability>
                <HostIP>192.168.1.20</HostIP>
                <CVE>CVE-2021-3156</CVE>
                <Name>Sudo Buffer Overflow</Name>
                <RiskLevel>High</RiskLevel>
                <CVSS>7.8</CVSS>
                <AffectedProduct>sudo</AffectedProduct>
                <Recommendation>Update sudo to version 1.9.5p2 or later</Recommendation>
            </Vulnerability>
        </Vulnerabilities>
        <Software>
            <SoftwareItem>
                <HostIP>192.168.1.10</HostIP>
                <ProductName>Microsoft IIS</ProductName>
                <Version>10.0</Version>
            </SoftwareItem>
            <SoftwareItem>
                <HostIP>192.168.1.20</HostIP>
                <ProductName>Nginx</ProductName>
                <Version>1.18.0</Version>
            </SoftwareItem>
        </Software>
        <Ports>
            <Port>
                <HostIP>192.168.1.10</HostIP>
                <Number>80</Number>
                <Protocol>TCP</Protocol>
                <Service>HTTP</Service>
            </Port>
            <Port>
                <HostIP>192.168.1.10</HostIP>
                <Number>443</Number>
                <Protocol>TCP</Protocol>
                <Service>HTTPS</Service>
            </Port>
            <Port>
                <HostIP>192.168.1.20</HostIP>
                <Number>22</Number>
                <Protocol>TCP</Protocol>
                <Service>SSH</Service>
            </Port>
        </Ports>
    </ScanResult>
    """
    
    print("=" * 60)
    print("Тестирование парсера RedCheck XML")
    print("=" * 60)
    
    parser = RedCheckXMLParser()
    
    try:
        result = parser.parse_string(test_xml)
        
        print(f"\n📊 Найдено хостов: {len(result['hosts'])}")
        for host in result['hosts']:
            print(f"   • {host['ip']} ({host['hostname']}) - {host['os']}")
        
        print(f"\n🔴 Найдено уязвимостей: {len(result['vulnerabilities'])}")
        for vuln in result['vulnerabilities']:
            print(f"   • [{vuln['risk_level']}] {vuln['cve']}: {vuln['name']}")
            print(f"     Хост: {vuln['ip']}, CVSS: {vuln['cvss']}")
        
        print(f"\n📦 Найдено записей ПО: {len(result['software'])}")
        for sw in result['software']:
            print(f"   • {sw['name']} v{sw['version']} на {sw['ip']}")
        
        print(f"\n🔌 Найдено портов: {len(result['ports'])}")
        for port in result['ports']:
            print(f"   • {port['ip']}:{port['port']}/{port['protocol']} - {port['service']}")
        
        print("\n" + "=" * 60)
        print("✅ Тестирование завершено успешно!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Ошибка при тестировании: {e}")
