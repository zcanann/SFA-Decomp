#include "dlls/objects/529.h"
#include "dlls/objects/common/vehicle.h"

/*
 * DLL 0x0211 - wall crawler enemy logic.
 *
 * Each crawler waits at its spawn point, dives toward a nearby target,
 * and then attacks or retreats according to its variant flags.
 */
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dlls/object_descriptor.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dlls/objects/196_Tricky.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/maketex_random_api.h"
#include "main/maketex_timer_api.h"
#include "main/obj_message.h"
#include "main/object_update_list.h"
#include "main/objhits.h"
#include "main/dll/path_control_interface.h"

f32 gWallCrawlerSpeedCap = 0.1f;
u8 sWallCrawlerCollisionBone[3] = {0x41, 0x20, 0};

#define WMWALLCRAWLER_OBJGROUP        3
#define WMWALLCRAWLER_PARTFX          0x1a3

/* state->flags, from the per-variant table gWallCrawlerVariantFlags */
#define WMWALLCRAWLER_FLAG_START_ACTIVE   0x1   /* spawn already diving (rotZ 0) */
#define WMWALLCRAWLER_FLAG_PATH_CONTROL   0x2   /* drive movement through gPathControlInterface */
#define WMWALLCRAWLER_FLAG_FLOOR_SNAP     0x4   /* snap Y to the nearest floor (trackGetHeight) */
#define WMWALLCRAWLER_FLAG_TIMED_EXPLODE  0x8   /* burst into particles when explodeTimer expires */
#define WMWALLCRAWLER_FLAG_TARGET_NEAREST 0x10  /* chase the nearest group-10 object, not the player */
#define WMWALLCRAWLER_FLAG_CLAMP_SPEED    0x20  /* cap velocity at gWallCrawlerSpeedCap */
#define WMWALLCRAWLER_FLAG_FADE_IN        0x40  /* spawn at alpha 0, fade in during render */
#define WMWALLCRAWLER_FLAG_NO_RETREAT     0x80  /* ignore lifeTimer (never re-perch/expire) */
#define WMWALLCRAWLER_FLAG_DEATH_ANIM     0x100 /* play the death anim instead of despawning */
#define WMWALLCRAWLER_FLAG_TRICKY_FLEE    0x200 /* flee when Tricky closes in; random re-dive */
#define WMWALLCRAWLER_FLAG_ATTACK_MOVE    0x400 /* lunge (anim move 2) when close */

#define WMWALLCRAWLER_MSG_PLAYER_BURST 0x60004 /* knock the player back with a burst hit */

#define WMWALLCRAWLER_PLACEMENT_IDENT(obj) (*(void**)((obj)->anim.placementDataAddress + offsetof(ObjPlacement, ident)))

/* state->mode */
enum {
    WMWALLCRAWLER_MODE_IDLE = 0,    /* perched at spawn height */
    WMWALLCRAWLER_MODE_DESCEND = 1, /* dropping to home height */
    WMWALLCRAWLER_MODE_CHASE = 3,   /* tracking the target along the surface */
    WMWALLCRAWLER_MODE_FLEE = 5,    /* reversed away from the target, life timer running */
    WMWALLCRAWLER_MODE_DIE = 6      /* death anim, then free/hide */
};

u8 gWallCrawlerHitCount;

int wmwallcrawler_animEventCallback(GameObject* obj) {
    ((WmwallcrawlerState*)obj->extra)->mode = WMWALLCRAWLER_MODE_DESCEND;
    return 0;
}

void wmwallcrawler_alignToFloorNormal(GameObject* obj, TrackGroundHit* floorHit) {
    MatrixTransform mtx;
    f32 in[3];
    u16 ang, ang2;
    in[0] = floorHit->normalX;
    in[1] = floorHit->normalY;
    in[2] = floorHit->normalZ;
    mtx.x = 0.0f;
    mtx.y = 0.0f;
    mtx.z = 0.0f;
    mtx.scale = 1.0f;
    mtx.rotZ = 0;
    mtx.rotY = 0;
    mtx.rotX = obj->anim.rotX;
    vecRotateZXY(&mtx.rotX, in);
    ang = getAngle(in[0], in[1]);
    ang2 = getAngle(in[2], in[1]);
    obj->anim.rotY = ang2;
    obj->anim.rotZ = ang;
}

int wmwallcrawler_getExtraSize(void) {
    return sizeof(WmwallcrawlerState);
}

int wmwallcrawler_getObjectTypeId(void) {
    return 0x0;
}

void wmwallcrawler_free(GameObject* obj) {
    objFreeObjectType(obj, WMWALLCRAWLER_OBJGROUP);
}

void wmwallcrawler_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 vis) {
    ObjAnimComponent* objAnim = &(obj)->anim;
    WmwallcrawlerState* state = obj->extra;
    if ((state->flags & WMWALLCRAWLER_FLAG_FADE_IN) != 0 && objAnim->alpha < 0xff) {
        if (objAnim->alpha > 0xff - framesThisStep) {
            objAnim->alpha = 0xff;
            state->flags &= ~WMWALLCRAWLER_FLAG_FADE_IN;
        } else {
            objAnim->alpha += framesThisStep;
        }
    }
    if (vis != 0 && state->despawnTimer == 0) {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void wmwallcrawler_hitDetect(GameObject* obj) {
    WmwallcrawlerState* state = (obj)->extra;
    f32 stk = 100000.0f;
    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
        if ((state->flags & WMWALLCRAWLER_FLAG_DEATH_ANIM) != 0) {
            state->mode = WMWALLCRAWLER_MODE_DIE;
        } else if (WMWALLCRAWLER_PLACEMENT_IDENT(obj) == 0) {
            ObjHits_DisableObject(obj);
            Obj_FreeObject(obj);
        } else {
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
            objFreeObjectType(obj, WMWALLCRAWLER_OBJGROUP);
            (obj)->anim.flags = (obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
        }
    } else if (state->hitBits.hit != 0) {
        GameObject* target;
        if ((state->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) == 0) {
            target = (GameObject*)Obj_GetPlayerObject();
        } else {
            target = objGetNearestTypeTo(VEHICLE_OBJECT_GROUP, obj, &stk);
        }
        ObjHits_RecordObjectHit(target, obj, 0xb, 1, 0);
        state->mode = WMWALLCRAWLER_MODE_DIE;
        state->hitBits.hit = 0;
    }
}

void wmwallcrawler_update(GameObject* obj) {
    WmwallcrawlerState* state;
    int bestIdx;
    GameObject* ob;
    GameObject* player;
    f32 speed;
    int k;
    int hitCount;
    GameObject* tricky;
    u8 sum;
    int ang;
    f32 dist;
    f32 sq;
    s8 mode;
    TrackGroundHit** list;
    f32 best;
    f32 d;
    f32 dy;
    f32 dz;

    ob = obj;
    state = ob->extra;
    bestIdx = 0;
    speed = 1.0f;
    sum = 0;
    list = 0;
    best = 10000.0f;
    player = (state->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) == 0
                 ? Obj_GetPlayerObject()
                 : objGetNearestTypeTo(VEHICLE_OBJECT_GROUP, ob, &best);
    if (player != 0) {
        sq = mainGetBit(0x789);
        gWallCrawlerSpeedCap = 0.1f * sq + 0.1f;
        if (state->mode == WMWALLCRAWLER_MODE_DIE) {
            ob->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            if (ob->anim.currentMove != 1) {
                ObjAnim_SetCurrentMove(ob, 1, 0.0f, 0);
                Sfx_PlayFromObject((GameObject*)ob, SFXTRIG_id_73);
            }
            if (ob->anim.currentMoveProgress > 0.4f) {
                ob->anim.rootMotionScale *= 0.95f;
            }
            if (ObjAnim_AdvanceCurrentMove(ob, 0.01f, framesThisStep, NULL) != 0) {
                if (state->counterGameBit != 0 && state->counterGameBit != -1) {
                    mainSetBits(state->counterGameBit, mainGetBit(state->counterGameBit) + 1);
                }
                if (WMWALLCRAWLER_PLACEMENT_IDENT(ob) == 0) {
                    ObjHits_DisableObject((GameObject*)ob);
                    Obj_FreeObject((GameObject*)ob);
                } else {
                    Obj_RemoveFromUpdateList((GameObject*)ob);
                    ObjHits_DisableObject((GameObject*)ob);
                    objFreeObjectType(ob, WMWALLCRAWLER_OBJGROUP);
                    ob->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
            }
        } else {
            if ((state->flags & WMWALLCRAWLER_FLAG_TIMED_EXPLODE) != 0) {
                if (timerCountDown((f32*)&state->explodeTimer) != 0) {
                    for (k = 0; k < 0x1e; k++) {
                        (*gPartfxInterface)->spawnObject((void*)ob, WMWALLCRAWLER_PARTFX, NULL, 0, -1, NULL);
                    }
                    s16toFloat((f32*)&state->despawnTimer, 100);
                    return;
                }
                if (timerCountDown((f32*)&state->despawnTimer) != 0) {
                    ob->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                    if (WMWALLCRAWLER_PLACEMENT_IDENT(ob) == 0) {
                        ObjHits_DisableObject((GameObject*)ob);
                        Obj_FreeObject((GameObject*)ob);
                    } else {
                        Obj_RemoveFromUpdateList((GameObject*)ob);
                        ObjHits_DisableObject((GameObject*)ob);
                        objFreeObjectType(ob, WMWALLCRAWLER_OBJGROUP);
                        ob->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    }
                    return;
                }
            }
            for (k = 0; k < 6; k++) {
                sum += mainGetBit(k + 0x2aa);
            }
            if (sum >= 6) {
                if (WMWALLCRAWLER_PLACEMENT_IDENT(ob) == 0) {
                    ObjHits_DisableObject((GameObject*)ob);
                    Obj_FreeObject((GameObject*)ob);
                } else {
                    Obj_RemoveFromUpdateList((GameObject*)ob);
                    ObjHits_DisableObject((GameObject*)ob);
                    objFreeObjectType(ob, WMWALLCRAWLER_OBJGROUP);
                    ob->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
            } else {
                if (timerIsActive((const f32*)&state->attackTimer) != 0) {
                    timerCountDown((f32*)&state->attackTimer);
                } else {
                    mode = state->mode;
                    if ((mode == WMWALLCRAWLER_MODE_CHASE || mode == WMWALLCRAWLER_MODE_DESCEND ||
                         mode == WMWALLCRAWLER_MODE_FLEE) &&
                        (state->flags & WMWALLCRAWLER_FLAG_NO_RETREAT) == 0) {
                        if (mode == WMWALLCRAWLER_MODE_FLEE) {
                            if (1000.0f > 30.0f + state->fleeChaseThreshold) {
                                state->mode = WMWALLCRAWLER_MODE_CHASE;
                                state->attackTimer = 0x14;
                            }
                        } else if (1000.0f < state->fleeChaseThreshold) {
                            state->lifeTimer -= framesThisStep;
                            if (randomChanceOneIn(0x32) != 0) {
                                Sfx_PlayFromObject((GameObject*)ob, SFXTRIG_id_74);
                            }
                            if (state->lifeTimer <= 0) {
                                if ((state->flags & WMWALLCRAWLER_FLAG_DEATH_ANIM) != 0) {
                                    state->mode = WMWALLCRAWLER_MODE_DIE;
                                } else if (WMWALLCRAWLER_PLACEMENT_IDENT(ob) == 0) {
                                    ObjHits_DisableObject((GameObject*)ob);
                                    Obj_FreeObject((GameObject*)ob);
                                } else {
                                    Obj_RemoveFromUpdateList((GameObject*)ob);
                                    ObjHits_DisableObject((GameObject*)ob);
                                    objFreeObjectType(ob, WMWALLCRAWLER_OBJGROUP);
                                    ob->anim.flags |= OBJANIM_FLAG_HIDDEN;
                                }
                                return;
                            }
                            if (state->mode != WMWALLCRAWLER_MODE_FLEE) {
                                Sfx_StopObjectChannel((GameObject*)ob, 0x10);
                                state->mode = WMWALLCRAWLER_MODE_FLEE;
                                ob->anim.velocityX = -ob->anim.velocityX * (d = 0.25f);
                                ob->anim.velocityZ = -ob->anim.velocityZ * d;
                            }
                        }
                    }
                    if ((state->flags & WMWALLCRAWLER_FLAG_TRICKY_FLEE) != 0 &&
                        state->mode != WMWALLCRAWLER_MODE_FLEE && (tricky = getTrickyObject()) != 0 &&
                        Vec_distance(&ob->anim.worldPosX, &tricky->anim.worldPosX) < 30.0f &&
                        TRICKY_INTERFACE(tricky)->isGuarding((GameObject*)tricky) != 0) {
                        state->mode = WMWALLCRAWLER_MODE_FLEE;
                        Sfx_PlayFromObject((GameObject*)ob, SFXTRIG_id_74);
                    }
                    if (state->mode == WMWALLCRAWLER_MODE_FLEE) {
                        if ((state->flags & WMWALLCRAWLER_FLAG_PATH_CONTROL) != 0) {
                            (*gPathControlInterface)->update((void*)ob, state, timeDelta);
                            (*gPathControlInterface)->apply((void*)ob, state);
                            (*gPathControlInterface)->advance((void*)ob, state, timeDelta);
                        }
                        sq = ob->anim.velocityX * ob->anim.velocityX + ob->anim.velocityZ * ob->anim.velocityZ;
                        if (sq != 0.0f) {
                            speed = sqrtf(sq);
                        }
                        state->animSpeed = -0.065f * speed;
                        ObjAnim_AdvanceCurrentMove(ob, state->animSpeed, framesThisStep, NULL);
                        ob->anim.localPosX = ob->anim.velocityX * timeDelta + ob->anim.localPosX;
                        ob->anim.localPosZ = ob->anim.velocityZ * timeDelta + ob->anim.localPosZ;
                        state->lifeTimer -= framesThisStep;
                        if ((state->flags & WMWALLCRAWLER_FLAG_FLOOR_SNAP) != 0) {
                            best = 10000.0f;
                            hitCount = trackGetHeight((GameObject*)ob, ob->anim.localPosX, ob->anim.localPosY,
                                                      ob->anim.localPosZ, &list, 0, 0);
                            for (k = 0; k < hitCount; k++) {
                                d = list[k]->height - ob->anim.localPosY;
                                if (d < 0.0f) {
                                    d *= -1.0f;
                                }
                                if (d < best) {
                                    bestIdx = k;
                                    best = d;
                                }
                            }
                            if (list != 0) {
                                ob->anim.localPosY = list[bestIdx]->height;
                                wmwallcrawler_alignToFloorNormal((GameObject*)ob, list[bestIdx]);
                            } else {
                                ob->anim.localPosY = state->homeY;
                            }
                        } else {
                            ob->anim.localPosY = state->homeY;
                        }
                        if ((state->flags & WMWALLCRAWLER_FLAG_NO_RETREAT) == 0 && state->lifeTimer <= 0) {
                            if ((state->flags & WMWALLCRAWLER_FLAG_DEATH_ANIM) != 0) {
                                state->mode = WMWALLCRAWLER_MODE_DIE;
                            } else {
                                state->mode = WMWALLCRAWLER_MODE_IDLE;
                                Sfx_StopObjectChannel((GameObject*)ob, 0x18);
                                ob->anim.localPosX = state->homeX;
                                ob->anim.localPosY = state->homeY + (f32)state->heightOffset;
                                ob->anim.localPosZ = state->homeZ;
                            }
                        } else if ((state->flags & WMWALLCRAWLER_FLAG_TRICKY_FLEE) != 0 &&
                                   randomGetRange(0, 0x14) == 0) {
                            state->mode = WMWALLCRAWLER_MODE_CHASE;
                            s16toFloat((f32*)&state->attackTimer, (s16)(randomGetRange(0, 0x14) + 0x32));
                        }
                    } else {
                        dist = Vec_xzDistance(&player->anim.worldPosX, &ob->anim.worldPosX);
                        if (dist < state->triggerRadius || mainGetBit(0x1d9) != 0) {
                            mode = state->mode;
                            if (mode == WMWALLCRAWLER_MODE_IDLE) {
                                state->mode = WMWALLCRAWLER_MODE_DESCEND;
                                s16toFloat((f32*)&state->attackTimer, 2);
                                ob->anim.rotZ = 0;
                            } else if (mode == WMWALLCRAWLER_MODE_DESCEND) {
                                if (ob->anim.velocityY > -10.0f) {
                                    ob->anim.velocityY = -0.1f * timeDelta + ob->anim.velocityY;
                                }
                                if (ob->anim.localPosY < state->homeY) {
                                    ob->anim.localPosY = state->homeY;
                                    ob->anim.velocityY = 0.0f;
                                    state->mode = WMWALLCRAWLER_MODE_CHASE;
                                    s16toFloat((f32*)&state->attackTimer, (s16)(randomGetRange(0, 0x14) + 0x32));
                                    state->triggerRadius *= 2.0f;
                                    ObjAnim_SetCurrentMove(ob, 0, 0.0f, 0);
                                }
                            } else if (mode == WMWALLCRAWLER_MODE_CHASE) {
                                Sfx_PlayFromObject((GameObject*)ob, SFXTRIG_id_47);
                                if ((state->flags & WMWALLCRAWLER_FLAG_PATH_CONTROL) != 0) {
                                    (*gPathControlInterface)->update((void*)ob, state, timeDelta);
                                    (*gPathControlInterface)->apply((void*)ob, state);
                                    (*gPathControlInterface)->advance((void*)ob, state, timeDelta);
                                }
                                if ((state->flags & WMWALLCRAWLER_FLAG_FLOOR_SNAP) != 0) {
                                    best = 10000.0f;
                                    hitCount = trackGetHeight((GameObject*)ob, ob->anim.localPosX, ob->anim.localPosY,
                                                              ob->anim.localPosZ, &list, 0, 0);
                                    for (k = 0; k < hitCount; k++) {
                                        d = list[k]->height - ob->anim.localPosY;
                                        if (d < 0.0f) {
                                            d *= -1.0f;
                                        }
                                        if (d < best) {
                                            bestIdx = k;
                                            best = d;
                                        }
                                    }
                                    if (list != 0) {
                                        ob->anim.localPosY = list[bestIdx]->height;
                                        wmwallcrawler_alignToFloorNormal((GameObject*)ob, list[bestIdx]);
                                    } else {
                                        ob->anim.localPosY = state->homeY;
                                    }
                                } else {
                                    ob->anim.localPosY = state->homeY;
                                }
                                dy = player->anim.localPosY - ob->anim.localPosY;
                                dz = player->anim.localPosZ - ob->anim.localPosZ;
                                sq = (player->anim.localPosX - ob->anim.localPosX) / (d = 300.0f);
                                ob->anim.velocityX = sq * timeDelta;
                                sq = dy / d;
                                ob->anim.velocityY = sq * timeDelta;
                                sq = dz / d;
                                ob->anim.velocityZ = sq * timeDelta;
                                if ((state->flags & WMWALLCRAWLER_FLAG_CLAMP_SPEED) != 0 &&
                                    sqrtf(ob->anim.velocityZ * ob->anim.velocityZ +
                                          (ob->anim.velocityX * ob->anim.velocityX +
                                           ob->anim.velocityY * ob->anim.velocityY)) > gWallCrawlerSpeedCap) {
                                    Vec3_Normalize(&ob->anim.velocityX);
                                    ob->anim.velocityX = ob->anim.velocityX * (timeDelta * gWallCrawlerSpeedCap);
                                    ob->anim.velocityY = ob->anim.velocityY * (timeDelta * gWallCrawlerSpeedCap);
                                    ob->anim.velocityZ = ob->anim.velocityZ * (timeDelta * gWallCrawlerSpeedCap);
                                }
                                if (ob->anim.currentMove == 0 && (state->flags & WMWALLCRAWLER_FLAG_ATTACK_MOVE) != 0 &&
                                    dist < 15.0f) {
                                    ObjAnim_SetCurrentMove(ob, 2, 0.0f, 0);
                                }
                                if (dist < 13.0f ||
                                    ((state->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) != 0 &&
                                     ((((ObjHitsPriorityState*)ob->anim.hitReactState)->flags & 8) != 0) &&
                                     dist < 50.0f)) {
                                    gWallCrawlerHitCount += 1;
                                    if (ob->anim.currentMove == 2 && ob->anim.currentMoveProgress > 0.3f &&
                                        ob->anim.currentMoveProgress < 0.7f) {
                                        ObjMsg_SendToObject((void*)player, WMWALLCRAWLER_MSG_PLAYER_BURST, (void*)ob,
                                                            1);
                                        gWallCrawlerHitCount = 0;
                                    }
                                    if (mainGetBit(0x1d9) != 0) {
                                        gWallCrawlerHitCount = 0;
                                    } else if (gWallCrawlerHitCount >= 3 ||
                                               ((state->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) != 0 &&
                                                gWallCrawlerHitCount >= 3)) {
                                        Sfx_PlayFromObject((GameObject*)ob, SFXTRIG_id_75);
                                        if ((state->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) == 0) {
                                            ObjMsg_SendToObject((void*)player, WMWALLCRAWLER_MSG_PLAYER_BURST,
                                                                (void*)ob, 1);
                                        } else {
                                            state->hitBits.hit = 1;
                                        }
                                        gWallCrawlerHitCount = 0;
                                    }
                                    if ((state->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) == 0) {
                                        d = 26.0f;
                                        ob->anim.localPosX = d * -ob->anim.velocityX + ob->anim.localPosX;
                                        ob->anim.localPosZ = d * -ob->anim.velocityZ + ob->anim.localPosZ;
                                    } else {
                                        d = 8.0f;
                                        ob->anim.localPosX = d * -ob->anim.velocityX + ob->anim.localPosX;
                                        ob->anim.localPosZ = d * -ob->anim.velocityZ + ob->anim.localPosZ;
                                    }
                                    s16toFloat((f32*)&state->attackTimer, (s16)(randomGetRange(0, 0x14) + 100));
                                }
                                ang = getAngle(player->anim.localPosX - ob->anim.localPosX,
                                               player->anim.localPosZ - ob->anim.localPosZ);
                                ob->anim.rotX = ang + 0x7fff;
                                sq = ob->anim.velocityX * ob->anim.velocityX + ob->anim.velocityZ * ob->anim.velocityZ;
                                if (sq != 0.0f) {
                                    speed = sqrtf(sq);
                                }
                                switch (ob->anim.currentMove) {
                                case 0:
                                    state->animSpeed = 0.065f * speed;
                                    break;
                                case 2:
                                    state->animSpeed = 0.03f;
                                    break;
                                case 1:
                                    state->animSpeed = 0.01f;
                                    break;
                                }
                                if (ObjAnim_AdvanceCurrentMove(ob, state->animSpeed, framesThisStep, NULL) != 0 &&
                                    ob->anim.currentMove != 0) {
                                    ObjAnim_SetCurrentMove(ob, 0, 0.0f, 0);
                                }
                                ob->anim.localPosX = ob->anim.velocityX * timeDelta + ob->anim.localPosX;
                                ob->anim.localPosZ = ob->anim.velocityZ * timeDelta + ob->anim.localPosZ;
                            }
                        } else if (state->mode == WMWALLCRAWLER_MODE_DESCEND) {
                            if (ob->anim.velocityY > -1.0f) {
                                ob->anim.velocityY = -0.01f * timeDelta + ob->anim.velocityY;
                            }
                            if (ob->anim.localPosY < state->homeY) {
                                ob->anim.localPosY = state->homeY;
                                ob->anim.velocityY = 0.0f;
                                state->mode = WMWALLCRAWLER_MODE_CHASE;
                                s16toFloat((f32*)&state->attackTimer, (s16)(randomGetRange(0, 0x14) + 0x32));
                                state->triggerRadius *= 2.0f;
                                ObjAnim_SetCurrentMove(ob, 0, 0.0f, 0);
                            }
                            ob->anim.localPosY = ob->anim.velocityY * timeDelta + ob->anim.localPosY;
                        }
                        if (state->mode == WMWALLCRAWLER_MODE_IDLE) {
                            ob->anim.localPosY = ob->anim.velocityY * timeDelta + ob->anim.localPosY;
                        }
                        if (randomChanceOneIn(0x32) != 0) {
                            Sfx_PlayFromObject((GameObject*)ob, SFXTRIG_id_76);
                        }
                    }
                }
            }
        }
    }
}

void wmwallcrawler_init(GameObject* obj, WmwallcrawlerMapData* mapData) {
    ObjAnimComponent* objAnim = &(obj)->anim;
    WmwallcrawlerState* state = (obj)->extra;
    u16 flags;
    objAddObjectType(obj, WMWALLCRAWLER_OBJGROUP);
    (obj)->anim.rotX = (s16)(mapData->rotXByte << 8);
    ObjMsg_AllocQueue(obj, 2);
    state->homeX = mapData->base.posX;
    state->homeY = mapData->base.posY;
    state->homeZ = mapData->base.posZ;
    state->triggerRadius = (f32)(int)mapData->triggerRadius;
    state->variant = mapData->variant;
    state->flags = gWallCrawlerVariantFlags[state->variant];
    storeZeroToFloatParam((f32*)&state->explodeTimer);
    storeZeroToFloatParam((f32*)&state->despawnTimer);
    storeZeroToFloatParam((f32*)&state->attackTimer);
    flags = state->flags;
    if ((flags & WMWALLCRAWLER_FLAG_START_ACTIVE) != 0) {
        (obj)->anim.rotZ = 0;
        state->mode = WMWALLCRAWLER_MODE_DESCEND;
    } else if ((flags & WMWALLCRAWLER_FLAG_TIMED_EXPLODE) != 0) {
        s16toFloat((f32*)&state->explodeTimer, 0x4b0);
        state->triggerRadius = 100.0f;
        (obj)->anim.rotZ = 0;
        state->mode = WMWALLCRAWLER_MODE_DESCEND;
    } else {
        s16toFloat((f32*)&state->attackTimer, 0x190);
        (obj)->anim.rotZ = -0x7fff;
        state->mode = WMWALLCRAWLER_MODE_IDLE;
    }
    if ((state->flags & WMWALLCRAWLER_FLAG_FADE_IN) != 0) {
        objAnim->alpha = 0;
    }
    state->animSpeed = 0.0f;
    state->heightOffset = mapData->heightOffset;
    (obj)->anim.localPosY = mapData->base.posY + (f32)(int)state->heightOffset;
    state->lifeTimer = (s16)(randomGetRange(0, 0x50) + 0x190);
    state->fleeChaseThreshold = 80.0f;
    state->counterGameBit = mapData->counterGameBit;
    if ((state->flags & WMWALLCRAWLER_FLAG_PATH_CONTROL) != 0) {
        state->pathState.subtype = CURVES_COLLISION_SUBTYPE_OBJECT;
        (*gPathControlInterface)->init((void*)state, 0, 0, 1);
        (*gPathControlInterface)
            ->setLocalPointCollision((void*)state, 1, gWallCrawlerPointCollision, sWallCrawlerCollisionBone, 4);
        (*gPathControlInterface)->attachObject((void*)obj, state);
        state->pathState.flags |= 0x40000u | CURVES_COLLISION_STATE_LOCAL_POINTS;
    }
    (obj)->animEventCallback = wmwallcrawler_animEventCallback;
    ObjHits_EnableObject(obj);
    ObjHits_SyncObjectPositionIfDirty(obj);
}

void wmwallcrawler_release(void) {
}

void wmwallcrawler_initialise(void) {
}

u16 gWallCrawlerVariantFlags[8] = {0x0000, 0x0002, 0x0004, 0x0001, 0x000C, 0x03F7, 0x0167, 0x050C};
f32 gWallCrawlerPointCollision[3] = {0.0f, 0.0f, 0.0f};

ObjectDescriptor10WithPadding gWM_WallCrawlerObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)wmwallcrawler_initialise,
        (ObjectDescriptorCallback)wmwallcrawler_release,
        0,
        (ObjectDescriptorCallback)wmwallcrawler_init,
        (ObjectDescriptorCallback)wmwallcrawler_update,
        (ObjectDescriptorCallback)wmwallcrawler_hitDetect,
        (ObjectDescriptorCallback)wmwallcrawler_render,
        (ObjectDescriptorCallback)wmwallcrawler_free,
        (ObjectDescriptorCallback)wmwallcrawler_getObjectTypeId,
        wmwallcrawler_getExtraSize,
    },
    0,
};
