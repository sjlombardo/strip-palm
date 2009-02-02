/*

			    P D B M A K E
			    =============

	Make a ready-to-install Palm .pdb file from the contents
	of one or more files on the desktop.  Binary files can be
	embedded into a single database record, while text files
	may be encoded as a database with one record per line,
	each null terminated with the original end of line sentinels
	trimmed.

			    by John Walker
		       http://www.fourmilab.ch/
		 This program is in the public domain

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "pdb.h"

#ifdef _WIN32
#include "getopt.h"
#else
#include <unistd.h>
#endif

static FILE *fi, *fo;

/*  Byte-order independent output of various length objects.  */

static void outbyte(int b)	      /* Single byte */
{
    putc(b, fo);
}

static void outshort(int s)	      /* Two byte short */
{
    putc(s >> 8, fo);
    putc(s, fo);
}

static void outlong(long l)	      /* Four byte long */
{
    putc(l >> 24, fo);
    putc(l >> 16, fo);
    putc(l >> 8, fo);
    putc(l, fo);
}

static void outbytes(char *b, int len) /* Sequence of bytes */
{
    fwrite(b, len, 1, fo);
}

static void outtext(char *b, int len)  /* Text string, zero padded to len */
{
    int sl = strlen(b);

    assert((sl + 1) <= len);
    outbytes(b, sl + 1);
    len -= sl + 1;
    while (len-- > 0) {
	outbyte(0);
    }
}

/*  TEXTRECORDINIT  --	Initialise extraction of records from
			in-memory text file.  */

static char *recptr;
static long reclen, ri;

static void textRecordInit(char *r, long l)
{
    recptr = r;
    reclen = l;
    ri = 0;
}

/*  TEXTRECORDNEXT  --	Return next record from in-memory text file.  Returns
			0 when end of file reached.  Truncates records as
			required.  Understands PC, Mac, Unix, and VAX end of
			line conventions.  If called with a dest argument
                        of NULL, doesn't copy the text; this can be used
			to count lines in a text buffer.  When dest is
			NULL, destl is irrelevant.  */
		       
static int textRecordNext(char *dest, int destl)
{
#define isEOL(c)    (((c) == '\r') || ((c) == '\n'))
    long rend, rl;
    
    if (ri >= reclen) {
	return 0;
    }
    
    for (rend = ri; (rend < reclen) && (!isEOL(recptr[rend])); rend++)
	;
	
    rl = rend - ri;
    if (dest != NULL) {
	if (rl == 0) {
	    *dest = 0;
	} else {
	    if (rl < (destl - 1)) {
		memcpy(dest, recptr + ri, rl);
		dest[rl] = 0;
	    } else {
		memcpy(dest, recptr + ri, destl - 1);
		dest[destl - 1] = 0;
	    }
	}
    }
    ri = rend + 1;
    if ((ri < reclen) && (isEOL(recptr[ri]) && (recptr[ri - 1] != recptr[ri]))) {
	ri++;
    }
    return 1;
}		      

/*  TEXTRECORDCOUNT  --  Count number of text lines in in-memory buffer.  */

static int textRecordCount(char *r, long l)
{
    int n = 0;

    textRecordInit(r, l);
    while (textRecordNext(NULL, 0L)) {
	n++;
    }
    return n;
}

/*  STRPAD  --	Pack an option string into a zero-padded buffer of
		a given length.  */

static char *strpad(int option, char *arg, int len)
{
    char *parg;

    if (((int) strlen(arg)) > len) {
        fprintf(stderr, "Argument to -%c option exceeds %d character maximum length.\n", option, len);
	exit(2);
    }

    /*	If the string fills the buffer or is one character shorter
        we can use as-is, taking advantage of the "natural pad"
	in the one character less case.  */

    if ((((int) strlen(arg)) == len) || (((int) strlen(arg)) == (len - 1))) {
	return arg;
    }

    /*	Otherwise, we need to allocate a buffer of the required
	length and copy the argument string to it, adding zero
	fill for the balance of the buffer.  */

    parg = malloc(len);
    if (parg == NULL) {
        fprintf(stderr, "Cannot allocate %d byte buffer for %c option argument.\n", len, option);
	exit(1);
    }
    memset(parg, 0, len);
    strcpy(parg, arg);
    return parg;
}

/*  USAGE  --  Print how-to-call information.  */

static void usage(void)
{
    fprintf(stderr, "pdbmake [options] ifile [ofile] \n");
    fprintf(stderr, "Embed file in Palm Computing(R) Platform PDB file.\n");
    fprintf(stderr, "   Options:\n");
    fprintf(stderr, "       -a             Text file: one record per line\n");
    fprintf(stderr, "       -b             Set backup flag\n");
    fprintf(stderr, "       -c crid        Creator ID (application unique)\n");
    fprintf(stderr, "       -n name        Database name (max 32 characters)\n");
    fprintf(stderr, "       -r             Mark read only\n");
    fprintf(stderr, "       -t type        Database type for application\n");
    fprintf(stderr, "       -u             Print this message\n");
    fprintf(stderr, "       -w             Raw binary (no length before binary data)\n");
    fprintf(stderr, "by John Walker (http://www.fourmilab.ch/)\n");
    fprintf(stderr, "This program is in the public domain.\n");
}

/*  Main program.  */

int main(int argc, char *argv[])
{
    extern char *optarg;
    extern int optind;

    char *inname,		      /* Input file name */
	 *outname,		      /* Output file name */
         *dbname = "Database-PdbM",   /* Database name on Palm */
         *creator = "PdbM",           /* Creator ID */
         *dtype = "PdbM";             /* Application database type */
    short pdbflags = 0; 	      /* Database flags */
    static char pdbext[] = ".pdb";    /* Default output file extension */
    int i, opt, rawBinary = 0, text = 0, textlines;
    long inflen, today;
    char *dbuf, *record;

    while ((opt = getopt(argc, argv, "abc:n:rt:uw")) != -1) {
	switch (opt) {
            case 'a':                 /* -a       ASCII text file mode */
		text = 1;
		break;

            case 'b':                 /* -b       Set backup flag */
		pdbflags |= pdbBackupFlag;
		break;

            case 'c':                 /* -c crid  Creator ID */
		creator = strpad(opt, optarg, 4);
		break;

            case 'n':                 /* -n name  Database name */
		dbname = strpad(opt, optarg, 32);
		break;

            case 'r':                 /* -r       Set read-only flag */
		pdbflags |= pdbReadOnlyFlag;
		break;

            case 't':                 /* -t type  Database type */
		dtype = strpad(opt, optarg, 4);
		break;

            case 'u':
		usage();
		return 0;

            case 'w':                 /* -w       Raw binary (no length before data) */
		rawBinary = 1;
		break;

            case '?':
		usage();
		return 2;
	}
    }

    i = 0;

    for (; optind < argc; optind++) {
	switch (i) {
	    case 0:
		inname = argv[optind];
		break;

	    case 1:
		outname = argv[optind];
		break;
	}
	i++;
    }

    /* Error if no input file name specified. */

    if (i == 0) {
        fprintf(stderr, "No input file name specified.\n");
	usage();
	return 2;
    }

    /* If no output file name specified, synthesise by replacing
       input file extension with ".pdb" or appending ".pdb" if
       the input file has no extension. */

    if (i == 1) {
	char *ext;

	outname = malloc(strlen(inname) + 5);
	if (outname == NULL) {
            fprintf(stderr, "Unable to allocate output file name buffer.\n");
	    return 1;
	}
	strcpy(outname, inname);
        ext = strrchr(outname, '.');
	if (ext == NULL) {
	    strcat(outname, pdbext);
	} else {
	    strcpy(ext, pdbext);
	}
    }

    fi = fopen(inname, "rb");
    if (fi == NULL) {
        fprintf(stderr, "Cannot open input file %s.\n", inname);
	return 2;
    }

    /* Read input file into memory.  Since the target is
       a handheld with far less memory than this desktop,
       there're no reason to worry about whether the file
       will fit in memory here. */

    fseek(fi, 0L, 2);
    inflen = ftell(fi); 	      /* Input file length */
    rewind(fi);
    dbuf = malloc(inflen);
    if (dbuf == NULL) {
        fprintf(stderr, "Unable to allocate %ld byte I/O buffer.\n", inflen);
	return 1;
    }
    fread(dbuf, inflen, 1, fi);
    fclose(fi);

    if (text) {
	textlines = textRecordCount(dbuf, inflen);
    }

    fo = fopen(outname, "wb");
    if (fo == NULL) {
        fprintf(stderr, "Cannot create output file %s.\n", outname);
	return 2;
    }

    /* Create PDB file header. */

    time(&today);

    outtext(dbname, kMaxPDBNameSize); /* name */
    outshort(pdbflags); 	      /* flags */
    outshort(0);		      /* version */
    outlong(today + timeOffset);      /* creationTime */
    outlong(today + timeOffset);      /* modificationTime */
    outlong(0); 		      /* backupTime */
    outlong(0); 		      /* modificationNumber */
    outlong(0); 		      /* appInfoOffset */
    outlong(0); 		      /* sortInfoOffset */
    outbytes(dtype, 4); 	      /* type */
    outbytes(creator, 4);	      /* Creator */
    outlong(0); 		      /* uniqueID */
    outlong(0); 		      /* nextRecordID */
    outshort(text ? textlines : 1);   /* numRecords */

    /* Create PDB record entry. */

    if (text) {
	long roffset = kPDBHeaderSize + (textlines * kPDBRecordEntrySize) + 2;

	record = malloc(inflen); /* File may be just one line, after all. */
	if (record == NULL) {
            fprintf(stderr, "Unable to allocate %ld bytes for record buffer.\n", inflen);
	}
	textRecordInit(dbuf, inflen);
	for (i = 0; i < textlines; i++) {
	    outlong(roffset);		 /* offset */
	    outlong(i); 		 /* attr, uniqueID:24 */
	    textRecordNext(record, inflen);
	    roffset += strlen(record) + 1;
	}
    } else {
	outlong(kPDBFirstRecordOffset);   /* offset */
	outlong(0);			  /* attr, uniqueID:24 */
    }

    /* Emit two pad bytes before first record. */

    outbyte(0);
    outbyte(0);

    /* From now on we're creating the content of the database. */

    if (!text) {
	if (!rawBinary) {

	    /* As a courtesy to the Palm application, precede a binary
	       record with its length, as a long. */

	    outlong(inflen);
	}
	outbytes(dbuf, inflen);
    } else {
	textRecordInit(dbuf, inflen);
	for (i = 0; i < textlines; i++) {
	    textRecordNext(record, inflen);
	    outbytes(record, strlen(record) + 1);
	}
	free(record);
    }

    free(dbuf);
    fclose(fo);

    return 0;
}
