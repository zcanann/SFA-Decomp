#ifndef MAIN_OBJECT_H_
#define MAIN_OBJECT_H_

#include "main/dll/objpathtransform_struct.h"
#include "main/dll/objmodel_types.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/engine_8001746C_phantoms.h"
#include "main/mapEvent.h"
#include "main/object_transform.h"
#include "main/objseq.h"
#include "main/objlib.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "main/gameplay_runtime.h"
#include "main/mm.h"
#include "main/texture.h"
#include "main/camera.h"
#include "main/sfa_extern_decls.h"

void* getTablesBinEntry(int i);
u8* loadObjectFile(int id);
int objGetTotalDataSize(void* tmpl, u8* def, s16* data, int flags);
void Obj_UpdateModelBlendStates(void);

#endif
