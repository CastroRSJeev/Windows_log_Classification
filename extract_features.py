import pandas as pd
import numpy as np
import ipaddress

def classify_ip(ip):
    try:
        if pd.isna(ip) or ip == '-': return 'Unknown'
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback: return 'Localhost'
        if ip_obj.is_private: return 'Private'
        if ip_obj.is_reserved: return 'Reserved'
        if str(ip) == '0.0.0.0': return 'Wildcard'
        return 'External'
    except:
        return 'Unknown'

def get_process_risk_score(path):
    if pd.isna(path): return 0.5
    path_lower = str(path).lower()
    if 'temp' in path_lower or 'appdata' in path_lower or 'users' in path_lower:
        return 1.0
    if 'system32' in path_lower or 'program files' in path_lower:
        return 0.1
    return 0.5

def count_risk_keywords(cmd):
    if pd.isna(cmd): return 0
    cmd_lower = str(cmd).lower()
    keywords = ['-enc', 'encodedcommand', 'rundll32', 'whoami', 'net user', 'net localgroup', 'powershell', 'cmd /c', 'downloadstring', 'iex']
    return sum(1 for kw in keywords if kw in cmd_lower)

def is_sensitive_priv(priv_list):
    if pd.isna(priv_list): return 0
    sensitive = ['SeDebugPrivilege', 'SeImpersonatePrivilege', 'SeTcbPrivilege', 'SeTakeOwnershipPrivilege']
    return 1 if any(s in str(priv_list) for s in sensitive) else 0

def extract_features(data):
    """
    Extracts Tier 1-4 features from the log dataframe.
    """
    # Working copy and basic setup
    df = pd.DataFrame()
    
    # Ensure datetime sorting for stateful features
    data['@timestamp'] = pd.to_datetime(data['@timestamp'], errors='coerce')
    data = data.sort_values('@timestamp')
 
    df['event_id'] = data['EventID']   
    df['process_name'] = data['ProcessName'].fillna(data['NewProcessName']).fillna(data['Image']).fillna(data['Application'])
    df['hostname'] = data['Hostname']
    
    def get_hostname_role(name):
        if pd.isna(name): return 'Unknown'
        s = str(name).lower()
        return 'Workstation' if any(x in s for x in ['workstation','laptop','pc']) else 'Server' if any(x in s for x in ['server','dc']) else 'Other'
    
    df['hostname_role'] = df['hostname'].apply(get_hostname_role)
    df['event_type'] = data['EventType']
    df['hour_of_day'] = data['@timestamp'].dt.hour
    df['day_of_week'] = data['@timestamp'].dt.day_name()
    df['user_context'] = data['SubjectUserName'].fillna(data['TargetUserName'])
    
    mask_admin = pd.Series(0, index=data.index)
    if 'IntegrityLevel' in data.columns:
        mask_admin |= data['IntegrityLevel'].astype(str).str.contains('High|System', case=False, na=False)
    if 'ElevatedToken' in data.columns:
        mask_admin |= data['ElevatedToken'].astype(str).str.contains('Yes|True', case=False, na=False)
    df['is_admin_process'] = mask_admin.astype(int)


    df['dest_port'] = data['DestPort'].fillna(0).astype(int)
    
    
    unique_src = data['SourceAddress'].dropna().unique()
    src_map = {ip: classify_ip(ip) for ip in unique_src}
    df['source_ip_type'] = data['SourceAddress'].map(src_map).fillna('Unknown')
    
    unique_dst = data['DestAddress'].dropna().unique()
    dst_map = {ip: classify_ip(ip) for ip in unique_dst}
    df['dest_ip_type'] = data['DestAddress'].map(dst_map).fillna('Unknown')
    
    df['user_id'] = data.get('SubjectUserSid', 'Unknown')
    df['process_path_risk_score'] = data['Image'].apply(get_process_risk_score)

   
    df['command_line_risk_keywords'] = data.get('CommandLine', '').apply(count_risk_keywords)
    df['parent_process_name'] = data.get('ParentProcessName', '')
    
   
    def get_ext_risk(filename):
        if pd.isna(filename): return 0
        ext = str(filename).split('.')[-1].lower() if '.' in str(filename) else ''
        return 1 if ext in ['exe', 'dll', 'ps1', 'bat', 'vbs', 'scr'] else 0
    df['file_extension_risk'] = data.get('TargetFilename', '').apply(get_ext_risk)
    
    df['logon_type'] = data.get('LogonType', -1)
    
    # Registry Path Type
    def get_reg_type(path):
        if pd.isna(path): return 'Normal'
        p = str(path).lower()
        if 'run' in p or 'runonce' in p or 'services' in p: return 'Persistence'
        return 'Normal'
    df['registry_path_type'] = data.get('TargetObject', '').apply(get_reg_type)
    
    df['is_sensitive_privilege'] = data.get('PrivilegeList', '').apply(is_sensitive_priv)


    try:
        data_sorted = data.sort_values('@timestamp').set_index('@timestamp')
        count_series = data_sorted.groupby('ProcessName')['EventID'].transform(lambda x: x.rolling('1h').count())
        df['event_count_1h'] = count_series.values
        df['unique_destinations_1h'] = 0 
        
    except Exception as e:
        print(f"Warning: Aggregation failed: {e}")
        df['event_count_1h'] = 0
        df['unique_destinations_1h'] = 0

    df['source_port'] = data.get('SourcePort')
    df['protocol'] = data.get('Protocol')
    df['is_outbound'] = df['dest_ip_type'].apply(lambda x: 1 if x == 'External' else 0)
    df['source_address'] = data.get('SourceAddress')
    df['dest_address'] = data.get('DestAddress')
    df['process_path'] = data.get('Image') 
    df['parent_process_path'] = data.get('ParentImage')
    df['command_line'] = data.get('CommandLine')
    df['file_path'] = data.get('TargetFilename') 
    df['file_name'] = df['file_path'].apply(lambda x: str(x).split('\\')[-1] if pd.notna(x) else '')
    df['file_extension'] = df['file_name'].apply(lambda x: str(x).split('.')[-1] if '.' in str(x) else '')
    
    return df

