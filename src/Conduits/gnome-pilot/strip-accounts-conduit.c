/*
 * $Id: strip-accounts-conduit.c,v 1.1.1.1 2005/08/08 14:51:26 lombardo Exp $
 *
 * Simple strip conduit for gnome-pilot implementing
 * copy_from_pilot.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <gdbm.h>

#include "gpilotd/gnome-pilot-conduit.h"
#include "gpilotd/gnome-pilot-conduit-standard.h"

#include "strip-conduit-capplet.h"

#define GET_CFG(s) ((ConduitCfg*)(gtk_object_get_data(GTK_OBJECT(s),"configuration")))

FILE *flog;

/***************************************************************
 * Forwards
 ***************************************************************/
GnomePilotConduit *conduit_get_gpilot_conduit(guint32 pilotId);
void conduit_destroy_gpilot_conduit(GnomePilotConduit *conduit);
static gint my_copy_from_pilot(GnomePilotConduitStandard *conduit, 
			       GnomePilotDBInfo *dbi, gpointer user_data);



/**************************************************************
 * Function: load_configuration
 *************************************************************/
static void load_configuration(ConduitCfg **c, guint32 pilotId)
{
    gchar *prefix;
    
    *c = g_new0(ConduitCfg,1);

    prefix=g_strdup_printf("/gnome-pilot.d/strip-conduit/Pilot_%u/",pilotId);
    
    gnome_config_push_prefix(prefix);
    (*c)->db_dir = gnome_config_get_string("db_dir");
    gnome_config_pop_prefix();

    if((*c)->db_dir != NULL) {
	if(mkdir((*c)->db_dir,(mode_t)0755) < 0) {
	    if(errno != EEXIST) {
		g_warning("Can't create strip directory (%s)",(*c)->db_dir);
	    }
	}
    }

    (*c)->pilotId = pilotId;
    g_free(prefix);
}

/**************************************************************
 * Function: destroy_configuration
 *************************************************************/
static void destroy_configuration(ConduitCfg **c)
{
    g_return_if_fail(c != NULL);
    g_return_if_fail(*c != NULL);

    if((*c)->db_dir) g_free((*c)->db_dir);
    g_free(*c);

    *c = NULL;
}

/**************************************************************
 * Function: conduit_get_gpilot_conduit
 * Description: this is the one of only two required gnome-pilot
 * function exported from the shared lib.  It initializes
 * the GnomePilotConduit structure.
 *************************************************************/

GnomePilotConduit *conduit_get_gpilot_conduit(guint32 pilotId) {
    GtkObject *retval;
    ConduitCfg *cfg;
    
    g_message("starting!");

    retval = gnome_pilot_conduit_standard_new("StripAccounts-SJLO",0x534A4C4F);
    gnome_pilot_conduit_construct(GNOME_PILOT_CONDUIT(retval),"Strip");
    g_assert(retval != NULL);

    load_configuration(&cfg, pilotId);
    gtk_object_set_data(retval,"configuration",cfg);

    gtk_signal_connect(retval,"copy_from_pilot",
		       (GtkSignalFunc)my_copy_from_pilot,cfg);

    return GNOME_PILOT_CONDUIT(retval);
}


/**************************************************************
 * Function: conduit_destroy_gpilot_conduit
 * Description: free up memory used in sync process
 *************************************************************/
void conduit_destroy_gpilot_conduit(GnomePilotConduit *conduit) {
    ConduitCfg *cfg;
    cfg=GET_CFG(conduit);
    destroy_configuration(&cfg);
    gtk_object_destroy(GTK_OBJECT(conduit));

}

/**************************************************************
 * Function: palm_db_to_gdbm
 * Description: copy palm db to a gdbm file
 *************************************************************/
static gint palm_db_to_gdbm(char *palm_db, char *gdbm_file,
			    GnomePilotDBInfo *dbi){
    int dbHandle;
    int index;
    guchar buffer[256];
    GDBM_FILE gf_localfile;
    datum dt_record, dt_key;

    g_message("Synchronizing %s",palm_db);
    
    gf_localfile=gdbm_open(gdbm_file, 512, GDBM_NEWDB, 0600, 0);
    if(!gf_localfile) {
	g_warning("Unable to create local database: %s",gdbm_file);
	return -1;
    }

    if(dlp_OpenDB(dbi->pilot_socket, 0, 0x80 | 0x40,
		  palm_db, &dbHandle) < 0) {
	g_warning("Unable to open remote database: %s", palm_db);
	gdbm_close(gf_localfile);
	return -1;
    }
    
    for (index = 0; ; index++) {
	int attr, category, len, ret;

	len=dlp_ReadRecordByIndex(dbi->pilot_socket, dbHandle, index, 
				  buffer, 0, 0, &attr, &category);
	if(len < 0)  /* Done? */
	    break;

	/* don't care about deleted records */
	if((attr & dlpRecAttrDeleted) || (attr & dlpRecAttrArchived))
	    continue;

	/* write the record in the buffer here */
	dt_record.dptr = buffer;
	dt_record.dsize = len;
	dt_key.dptr = (char *)&index;
	dt_key.dsize = sizeof(int);

	if(gdbm_store(gf_localfile,dt_key,dt_record,GDBM_INSERT) < 0) {
	    g_warning("Error inserting record.. aborting");
	    return -1;
	}
    }

    dlp_ResetLastSyncPC(dbi->pilot_socket);
    dlp_CloseDB(dbi->pilot_socket,dbHandle);

    g_message("Synchronized %d records from %s",index,palm_db);
    
    return 0;
}

/**************************************************************
 * Function: my_copy_from_pilot
 * Description: implements the copy_from_pilot sync method
 *************************************************************/
static gint my_copy_from_pilot(GnomePilotConduitStandard *conduit, 
			GnomePilotDBInfo *dbi, gpointer user_data) {
    ConduitCfg *cfg = user_data;
    gchar *localpath;

    g_message("Starting Copy From Pilot sync method");

    localpath = g_strdup_printf("%s/StripAccounts.gdb",cfg->db_dir);
    palm_db_to_gdbm("StripAccounts-SJLO",localpath,dbi);
    g_free(localpath);

    localpath = g_strdup_printf("%s/StripPassword.gdb",cfg->db_dir);
    palm_db_to_gdbm("StripPassword-SJLO",localpath,dbi);
    g_free(localpath);

    localpath = g_strdup_printf("%s/StripSystems.gdb",cfg->db_dir);
    palm_db_to_gdbm("StripSystems-SJLO",localpath,dbi);
    g_free(localpath);

    g_message("Completed synchronization");
    return 0;

}
