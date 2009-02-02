/*
 * $Id: strip-conduit-capplet.h,v 1.1.1.1 2005/08/08 14:51:26 lombardo Exp $
 */

#ifndef _STRIP_CONDUIT_CAPPLET_H_
#define _STRIP_CONDUIT_CAPPLET_H_

#ifdef EC_DEBUG
#define LOG(format,args...) g_log (G_LOG_DOMAIN, \
                                   G_LOG_LEVEL_MESSAGE, \
                                   "email: "##format, ##args)
#else
#define LOG(format,args...)
#endif

typedef struct {
    gchar *db_dir;
    guint32 pilotId;
} ConduitCfg;




#endif /* _STRIP_CONDUIT_CAPPLET_H_ */
