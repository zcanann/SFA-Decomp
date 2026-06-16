#ifndef MAIN_DLL_NW_NW_SHARED_H_
#define MAIN_DLL_NW_NW_SHARED_H_

/*
 * Shared definitions for the SnowHorn Wastes (map 'nwastes', 0x0A) object
 * DLLs. The static ice blocks (nwice, DLL 0x1A4) pair themselves against
 * the animated ice blocks (nwanimice, DLL 0x1A3) through these object
 * groups, so both TUs must agree on the group ids.
 */

#define NW_ICE_GROUP_ID 0x3c     /* nwice instances */
#define NW_ANIMICE_GROUP_ID 0x3d /* nwanimice instances, located by nwice */

#endif /* MAIN_DLL_NW_NW_SHARED_H_ */
