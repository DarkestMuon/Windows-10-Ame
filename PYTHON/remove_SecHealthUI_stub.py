import os, sqlite3

conn = sqlite3.connect(os.path.expandvars(r'%ProgramData%\Microsoft\Windows\AppRepository\StateRepository-Machine.srd'))

cursor = conn.execute(
    '''
    SELECT _PackageID, PackageFullName FROM main.Package
    WHERE PackageFullName LIKE "Microsoft.Windows.SecHealthUI%";
    '''
)
records_to_update = {}
for row in cursor:
    records_to_update[row[0]] = row[1]

cursor = conn.execute(
    '''
    SELECT name, sql FROM main.sqlite_master
    WHERE type = "trigger" AND tbl_name = "Package" AND name LIKE "TRG_AFTER_UPDATE%";
    '''
)
triggers_backup = {}
for row in cursor:
    triggers_backup[row[0]] = row[1]

# Delete update triggers for table "Package"
for TriggerName, TriggerSQL in triggers_backup.items():
    conn.execute(
        '''
        DROP TRIGGER %s;
        ''' % TriggerName
    )
    conn.commit()
    print('Trigger "%s" has been cleared.' % TriggerName)

# Set IsInbox to 0
for PackageID, PackageFullName in records_to_update.items():
    conn.execute(
        '''
        UPDATE main.Package SET IsInbox = 0 WHERE _PackageID = %d;
        ''' % PackageID
    )
    conn.commit()
    print('IsInbox of "%s" has been set to 0.' % PackageFullName)

# Restore triggers
for TriggerName, TriggerSQL in triggers_backup.items():
    conn.execute(
        '''
        %s;
        ''' % TriggerSQL
    )
    conn.commit()
    print('Trigger "%s" has been restored.' % TriggerName)

