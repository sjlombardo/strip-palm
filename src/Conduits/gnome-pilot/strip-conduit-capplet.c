/* 
 * $Id: strip-conduit-capplet.c,v 1.1.1.1 2005/08/08 14:51:26 lombardo Exp $
 * Copyright (C) 2000 Ron Pedde <ron@pedde.com>
 * 
 * capplet for gnome-pilot strip conduit
 * based on applets in the gnome-pilot distribution
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
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <pwd.h>
#include <sys/types.h>
#include <signal.h>
#include <gnome.h>

#include <capplet-widget.h>

#include <libgpilotdCM/gnome-pilot-conduit-management.h>
#include <libgpilotdCM/gnome-pilot-conduit-config.h>
#include <gpilotd/gnome-pilot-client.h>

#include "strip-conduit-capplet.h"

/* tell changes callbacks to ignore changes or not */
static gboolean ignore_changes=FALSE;

/* capplet widget */
static GtkWidget *capplet=NULL;

/* host/device/pilot configuration windows */
GtkWidget *cfgOptionsWindow=NULL;
GtkWidget *cfgStateWindow=NULL;
GtkWidget *dialogWindow=NULL;

gboolean activated,org_activation_state;
GnomePilotClient *gpc;
GnomePilotConduitManagement *conduit;
GnomePilotConduitConfig *conduit_config;

ConduitCfg *origState = NULL;
ConduitCfg *curState = NULL;

static void doTrySettings(GtkWidget *widget, ConduitCfg *conduitCfg);
static void doRevertSettings(GtkWidget *widget, ConduitCfg *conduitCfg);
static void doSaveSettings(GtkWidget *widget, ConduitCfg *conduitCfg);

static void readStateCfg(GtkWidget *w);
static void setStateCfg(GtkWidget *w);
static void readOptionsCfg(GtkWidget *w, ConduitCfg *state);
static void setOptionsCfg(GtkWidget *w, ConduitCfg *state);

gint pilotId;
CORBA_Environment ev;

/*********************************************************
 * Function: load_configuration
 * Description:  load configuration 
 *********************************************************/
static void load_configuration(ConduitCfg **c, guint32 pilotId) 
{
    gchar *prefix;
    guint i;

    *c = g_new0(ConduitCfg,1);

    prefix=g_strdup_printf("/gnome-pilot.d/strip-conduit/Pilot_%u/",pilotId);
    gnome_config_push_prefix(prefix);
    (*c)->db_dir = gnome_config_get_string("db_dir");
    gnome_config_pop_prefix();

    /* set default db dir */
    if((*c)->db_dir == NULL) {
	gchar *tmp;
	gnome_pilot_client_get_pilot_base_dir_by_id(gpc,pilotId,&tmp);
	(*c)->db_dir = g_strdup_printf("%s/strip/",tmp);
	g_free(tmp);
    }

    if(mkdir((*c)->db_dir,(mode_t)0755) < 0) {
	if(errno != EEXIST) {
	    /* Could this be? */
	    g_warning("Doh!  Can't make database directory %s",(*c)->db_dir);
	}
    }

    (*c)->pilotId = pilotId;
    g_free(prefix);
}


/*********************************************************
 * Function: copy_configuration
 * Description: copy a conduitCfg into another conduitCfg
 *********************************************************/
static void copy_configuration(ConduitCfg *d, ConduitCfg *c)
{
    g_return_if_fail(c!=NULL);
    g_return_if_fail(d!=NULL);

    if(d->db_dir) g_free(d->db_dir);
    d->db_dir = g_strdup(c->db_dir);
    d->pilotId = c->pilotId;
}

/*********************************************************
 * Function: dupe_configuration
 * Description: make a new conduitCfg
 *********************************************************/
static ConduitCfg *dupe_configuration(ConduitCfg *c) 
{
    ConduitCfg *d;
    g_return_val_if_fail(c!=NULL,NULL);
    d = g_new0(ConduitCfg,1);
    copy_configuration(d,c);
    return d;
}

/*********************************************************
 * Function: destroy_configuration
 * Description: free all memory associated with a conduitCfg
 *********************************************************/
static void destroy_configuration(ConduitCfg **c) 
{
    g_return_if_fail(c!=NULL);
    g_return_if_fail(*c!=NULL);

    g_free((*c)->db_dir);
    g_free(*c);

    *c = NULL;
}


/*********************************************************
 * Function: save_configuration
 * Description: save a ConduitCfg
 *********************************************************/
static void save_configuration(ConduitCfg *c) 
{
    gchar *prefix;

    g_return_if_fail(c!=NULL);
    
    prefix=g_strdup_printf("/gnome-pilot.d/strip-conduit/Pilot_%u/",pilotId);
    gnome_config_push_prefix(prefix);
    gnome_config_set_string("db_dir",c->db_dir);
    gnome_config_pop_prefix();
    gnome_config_sync();
    gnome_config_drop_all();
    g_free(prefix);
}

/*********************************************************
 * Function: doTrySettings
 * Description:  this gets run when the user presses
 * the 'try' button from gnomecc
 *********************************************************/
static void doTrySettings(GtkWidget *widget, ConduitCfg *conduitCfg)
{
    readStateCfg(cfgStateWindow);
    readOptionsCfg(cfgOptionsWindow, curState);
       
    if(activated) {
	/* who came up with constants that are
	 * like 60 characters long? */ 
	gnome_pilot_conduit_config_enable(conduit_config,
		GnomePilotConduitSyncTypeCopyFromPilot);
    } else {
      gnome_pilot_conduit_config_disable(conduit_config);
    }
}

/*********************************************************
 * Function: doSaveSettings
 * Description: this gets run when the user presses
 * the 'ok' button from gnomecc
 *********************************************************/
static void doSaveSettings(GtkWidget *widget, 
			   ConduitCfg *conduitCfg)
{
    doTrySettings(widget, conduitCfg);
    save_configuration(conduitCfg);
}


/*********************************************************
 * Function: doRevertSettings
 * Description: cancel button from gnomecc
 *********************************************************/
static void
doRevertSettings(GtkWidget *widget, ConduitCfg *conduitCfg)
{
    activated = org_activation_state;
    setStateCfg(cfgStateWindow);
}

/*********************************************************
 * Function: insert_dir_callback
 * Description: callback for the directory path
 *********************************************************/
static void insert_dir_callback (GtkEditable *editable, const gchar *text,
				 gint len, gint *position, void *data)
{
    gint i;
    gchar *curname;

    curname = gtk_entry_get_text(GTK_ENTRY(editable));
    if (*curname == '\0' && len > 0) {
	if (isspace(text[0])) {
	    gtk_signal_emit_stop_by_name(GTK_OBJECT(editable), "insert_text");
	    return;
	}
    } else {
	for (i=0; i<len; i++) {
	    if (isspace(text[i])) {
		gtk_signal_emit_stop_by_name(GTK_OBJECT(editable), 
					     "insert_text");
		return;
	    }
	}
    }
}

/*********************************************************
 * Function: insert_dir_callback2
 *********************************************************/

static void insert_dir_callback2(GtkEditable *editable, const gchar *text,
				 gint length, gint *position,
				 void *data)
{
    if (!ignore_changes)
        capplet_widget_state_changed(CAPPLET_WIDGET(capplet), TRUE);
}

/*********************************************************
 * Function: statechange_cb
 *********************************************************/
static void statechange_cb(GtkEditable *editable, const gchar *text,
			   gint length, gint *position,
			   void *data)
{
    if (!ignore_changes)
	capplet_widget_state_changed(CAPPLET_WIDGET(capplet), TRUE);
}
	

/*********************************************************
 * Function: about_cb 
 * Description:  not used
 *********************************************************/
void about_cb (GtkWidget *widget, gpointer data) {
  GtkWidget *about;
  const gchar *authors[] = {_("Ron Pedde <ron@pedde.com>"),NULL};
  
  about = gnome_about_new(_("Gnome Pilot Strip conduit"), VERSION,
			  _("(C) 2000 "),
			  authors,
			  _("Configuration utility for the Strip conduit.\n"
			    "see www.zetetic.net for more."),
			  _("gnome-unknown.xpm"));
  gtk_widget_show (about);
  
  return;
}

/*********************************************************
 * Function: toggled_cb
 *********************************************************/
static void toggled_cb(GtkWidget *widget, gpointer data) {
  if(!ignore_changes) {
    gtk_widget_set_sensitive(cfgOptionsWindow,GTK_TOGGLE_BUTTON(widget)->active);
    capplet_widget_state_changed(CAPPLET_WIDGET(capplet), TRUE);
  }
}

/*********************************************************
 * Function: createStateCfgWindow
 *********************************************************/
static GtkWidget *createStateCfgWindow(void)
{
    GtkWidget *vbox, *table;
    GtkWidget *entry, *label;
    GtkWidget *button;

    vbox = gtk_vbox_new(FALSE, GNOME_PAD);

    table = gtk_table_new(2, 2, FALSE);
    gtk_table_set_row_spacings(GTK_TABLE(table), 4);
    gtk_table_set_col_spacings(GTK_TABLE(table), 10);
    gtk_box_pack_start(GTK_BOX(vbox), table, FALSE, FALSE, GNOME_PAD);

    label = gtk_label_new(_("Enabled"));
    gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 1,2);

    button = gtk_check_button_new();
    gtk_object_set_data(GTK_OBJECT(vbox), "conduit_on_off", button);
    gtk_signal_connect(GTK_OBJECT(button), "toggled",
		       GTK_SIGNAL_FUNC(toggled_cb),
		       NULL);
    gtk_table_attach_defaults(GTK_TABLE(table), button, 1, 2, 1,2);

    return vbox;
}

/*********************************************************
 * Function: setStateCfg
 *********************************************************/
static void setStateCfg(GtkWidget *cfg)
{
    GtkWidget *button;
    gchar num[40];

    button = gtk_object_get_data(GTK_OBJECT(cfg), "conduit_on_off");

    g_assert(button!=NULL);

    ignore_changes = TRUE;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button),activated);
    gtk_widget_set_sensitive(cfgOptionsWindow,GTK_TOGGLE_BUTTON(button)->active);
    ignore_changes = FALSE;
}


/*********************************************************
 * Function: readStateCfg
 *********************************************************/
static void readStateCfg(GtkWidget *cfg)
{
  GtkWidget *button;

  button  = gtk_object_get_data(GTK_OBJECT(cfg), "conduit_on_off");
  
  g_assert(button!=NULL);

  activated = GTK_TOGGLE_BUTTON(button)->active;
}

/*********************************************************
 * Function: createCfgWindow
 *********************************************************/
static GtkWidget *createCfgWindow(void) 
{
    GtkWidget *vbox, *table;
    GtkWidget *entry, *label;
    
    vbox=gtk_vbox_new(FALSE, GNOME_PAD);
    
    table = gtk_table_new(2,1,FALSE);
    gtk_table_set_row_spacings(GTK_TABLE(table), 4);
    gtk_table_set_col_spacings(GTK_TABLE(table), 10);
    gtk_box_pack_start(GTK_BOX(vbox), table, FALSE, FALSE, GNOME_PAD);

    label = gtk_label_new(_("Database Directory"));
    gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 0, 1);

    entry = gtk_entry_new_with_max_length(128);
    gtk_object_set_data(GTK_OBJECT(vbox), "dir", entry);
    gtk_table_attach_defaults(GTK_TABLE(table), entry, 1, 2, 0, 1);
    
    gtk_signal_connect(GTK_OBJECT(entry), "insert_text",
		       GTK_SIGNAL_FUNC(insert_dir_callback),
		       NULL);

    gtk_signal_connect_after(GTK_OBJECT(entry), "insert_text",
			     GTK_SIGNAL_FUNC(statechange_cb),
			     NULL);

    gtk_signal_connect_after(GTK_OBJECT(entry), "delete_text",
			     GTK_SIGNAL_FUNC(statechange_cb),
			     NULL);

    return vbox;
}

/*********************************************************
 * Function: setOptionsCfg
 * Description: initialize the options portion of the
 * capplet from the config structure passed
 *********************************************************/
static void setOptionsCfg(GtkWidget *pilotcfg, ConduitCfg *state)
{
    GtkWidget *dir;
    dir = gtk_object_get_data(GTK_OBJECT(pilotcfg), "dir");
    
    g_assert(dir != NULL);

    ignore_changes = TRUE;
    gtk_entry_set_text(GTK_ENTRY(dir),state->db_dir);
    ignore_changes=FALSE;
}

/*********************************************************
 * Function: readOptionsCfg
 * Description: pull data from the dialog into the 
 * config 
 *********************************************************/
static void readOptionsCfg(GtkWidget *pilotcfg, ConduitCfg *state)
{
    GtkWidget *dir;

    dir = gtk_object_get_data(GTK_OBJECT(pilotcfg), "dir");
    state->db_dir = g_strdup(gtk_entry_get_text(GTK_ENTRY(dir)));
}

/*********************************************************
 * Function: pilot_capplet_setup
 *********************************************************/
static void pilot_capplet_setup(void)
{
    GtkWidget *frame, *table;

    capplet = capplet_widget_new();

    table = gtk_table_new(1, 2, FALSE);
    gtk_container_border_width(GTK_CONTAINER(table), GNOME_PAD);
    gtk_container_add(GTK_CONTAINER(capplet), table); 

    frame = gtk_frame_new(_("Conduit state"));
    gtk_container_border_width(GTK_CONTAINER(frame), GNOME_PAD_SMALL);
    gtk_table_attach_defaults(GTK_TABLE(table), frame, 0, 1, 0, 1);
    cfgStateWindow = createStateCfgWindow();
    gtk_container_add(GTK_CONTAINER(frame), cfgStateWindow);


    frame = gtk_frame_new(_("Strip Options"));
    gtk_container_border_width(GTK_CONTAINER(frame), GNOME_PAD_SMALL);
    gtk_table_attach_defaults(GTK_TABLE(table),frame,0,1,1,2);
    cfgOptionsWindow = createCfgWindow();
    gtk_container_add(GTK_CONTAINER(frame),cfgOptionsWindow);

    gtk_signal_connect(GTK_OBJECT(capplet), "try",
			GTK_SIGNAL_FUNC(doTrySettings), curState);
    gtk_signal_connect(GTK_OBJECT(capplet), "revert",
			GTK_SIGNAL_FUNC(doRevertSettings), curState);
    gtk_signal_connect(GTK_OBJECT(capplet), "ok",
			GTK_SIGNAL_FUNC(doSaveSettings), curState);
    gtk_signal_connect(GTK_OBJECT(capplet), "help",
			GTK_SIGNAL_FUNC(about_cb), NULL);


    setStateCfg(cfgStateWindow);
    setOptionsCfg(cfgOptionsWindow,curState);

    gtk_widget_show_all(capplet);
}

/*********************************************************
 * Function: run_error_dialog
 *********************************************************/
void run_error_dialog(gchar *mesg,...) {
  char tmp[80];
  va_list ap;

  va_start(ap,mesg);
  vsnprintf(tmp,79,mesg,ap);
  dialogWindow = gnome_message_box_new(mesg,GNOME_MESSAGE_BOX_ERROR,GNOME_STOCK_BUTTON_OK,NULL);
  gnome_dialog_run_and_close(GNOME_DIALOG(dialogWindow));
  va_end(ap);
}

/*********************************************************
 * Function: get_pilot_id_from_gpilotd
 *********************************************************/
gint get_pilot_id_from_gpilotd() {
	GList *pilots = NULL;
	gint pilot;
	int i,err;
  
	i=0;
	/* we don't worry about leaking here, so pilots isn't freed */
	switch(err = gnome_pilot_client_get_pilots(gpc,&pilots)) {
	case GPILOTD_OK: {
		if(pilots) {
			i=g_list_length(pilots);
			if(i==0) {
				run_error_dialog(_("No pilot configured, please choose the\n'Pilot Link Properties' capplet first."));
				return -1;
			} else {
				gnome_pilot_client_get_pilot_id_by_name(gpc,
									pilots->data, /* this is the first pilot */
									&pilot);
				if(i==1) {
					return pilot;
				}else {
					g_message("too many pilots...");
					/* need a choose here */
					return pilot;
				}
			}
		} else {
			run_error_dialog(_("No pilot configured, please choose the\n'Pilot Link Properties' capplet first."));
			return -1;
		}    
		break;
	}
	case GPILOTD_ERR_NOT_CONNECTED:
		run_error_dialog(_("Not connected to the gnome-pilot daemon"));
		return -1;
		break;
	default:
		g_warning("gnome_pilot_client_get_pilot_ids(...) = %d",err);
		run_error_dialog(_("An error occured when trying to fetch\npilot list from the gnome-pilot daemon"));
		return -1;
		break;
	}

}

/*********************************************************
 * Function: main
 *********************************************************/
int
main( int argc, char *argv[] )
{
    /* we're a capplet */
    gnome_capplet_init ("strip conduit control applet", NULL, argc, argv, 
			NULL,
			0, NULL);


    gpc = GNOME_PILOT_CLIENT(gnome_pilot_client_new());
    gnome_pilot_client_connect_to_daemon(gpc);
    
    pilotId = get_pilot_id_from_gpilotd();
    if(!pilotId) return -1;

    /* put all code to set things up in here */
    load_configuration(&origState,pilotId);
    curState = dupe_configuration(origState);

    /* put all code to set things up in here */
    conduit = gnome_pilot_conduit_management_new("strip1",GNOME_PILOT_CONDUIT_MGMT_ID);
    if (conduit==NULL) return -1;
    conduit_config = gnome_pilot_conduit_config_new(conduit,pilotId);
    org_activation_state = activated = gnome_pilot_conduit_config_is_enabled(conduit_config,NULL);
    
    pilot_capplet_setup();
    gnome_pilot_conduit_management_destroy(conduit);
    gnome_pilot_conduit_config_destroy(conduit_config);
    gnome_pilot_client_destroy(gpc);

    /* done setting up, now run main loop */
    capplet_gtk_main();
    return 0;
}    
