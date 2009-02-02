/*

                           PDB file format

        This should be used only for reference because it
        assumes no structure padding and big-endian
        byte alignment.  All I/O to the actual PDB file must
        be done with padding and byte order independent code.

*/

#define kMaxPDBNameSize         32
#define kPDBNameSuffix          ".PDB"
#define kDOSFilenameSize        12

#if PRAGMA_ALIGN_SUPPORTED
#pragma options align=packed
#endif

#define timeOffset  2082844886LU      /* Time offset from Unix time() values */

typedef struct PDBHeader
{
        char            name[kMaxPDBNameSize];
        unsigned short  flags;
        unsigned short  version;
        unsigned long   creationTime;
        unsigned long   modificationTime;
        unsigned long   backupTime;
        unsigned long   modificationNumber;
        unsigned long   appInfoOffset;
        unsigned long   sortInfoOffset;
        unsigned long   type;
        unsigned long   creator;
        unsigned long   uniqueID;
        unsigned long   nextRecordID;
        unsigned short  numRecords;
} PDBHeader;

#define kPDBHeaderSize  78

typedef struct PDBResourceEntry
{
        unsigned long   type;
        unsigned short  id;
        unsigned long   offset;
} PDBResourceEntry;

#define kPDBResourceEntrySize   10

typedef struct PDBRecordEntry
{
        unsigned long   offset;
        unsigned char   attr;
        unsigned long   uniqueID:24;
} PDBRecordEntry;

#define dmRecAttrDelete 0x80    /* Delete this record on next sync */
#define dmRecAttrDirty  0x40    /* Archive this record on next sync */
#define dmRecAttrBusy   0x20    /* Record is in use */
#define dmRecAttrSecret 0x10    /* Secret record, protected by password */

#define dmRecAttrCategoryMask 0x0F /* Mask to extract category from attribute */

#define kPDBRecordEntrySize     8

/*      PDB Format

        PBDHeader
        PDBResourceEntry|PDBRecordEntry [numRecords]
        2 bytes 
        AppInfo (if applicable)
        SortInfo (if applicable)
        DATA ENTRIES
*/

#define kPDBFirstResourceOffset (kPDBHeaderSize + kPDBResourceEntrySize + 2)
#define kPDBFirstRecordOffset   (kPDBHeaderSize + kPDBRecordEntrySize + 2)

enum PDBFlags {
        pdbResourceFlag = 0x0001,          /* Is this a resource file ? */
        pdbReadOnlyFlag = 0x0002,          /* Is database read only ? */
        pdbAppInfoDirtyFlag = 0x0004,      /* Is application info block dirty ? */
        pdbBackupFlag = 0x0008,            /* Back up to PC if no conduit defined */
        pdbOKToInstallNewer = 0x0010,      /* OK to install a newer version if current database open */
        pdbResetAfterInstall = 0x0020,     /* Must reset machine after installation */
        pdbStream = 0x0080,                /* Used for file streaming */
        pdbOpenFlag = 0x8000               /* Not closed properly */
};

enum PDBVersion {
        pdbVerReadOnly = 0x0001,
        pdbVerWrite = 0x0002,
        pdbVerReadWrite = 0x0003,
        pdbVerLeaveOpen = 0x0004,
        pdbVerExclusive = 0x0008,
        pdbVerShowSecret = 0x0010
};
