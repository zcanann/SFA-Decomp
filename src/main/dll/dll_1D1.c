#include "ghidra_import.h"
#include "main/dll/dll_1D1.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern int ObjHits_GetPriorityHit();
extern undefined4 FUN_80057690();

extern undefined4 DAT_802c2b58;
extern undefined4 DAT_802c2b5c;
extern undefined4 DAT_802c2b60;
extern undefined4 DAT_802c2b64;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4 DAT_803de868;
extern f32 lbl_803E5E78;

/*
 * --INFO--
 *
 * Function: FUN_801cd7dc
 * EN v1.0 Address: 0x801CD7DC
 * EN v1.0 Size: 1000b
 * EN v1.1 Address: 0x801CD80C
 * EN v1.1 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cd7dc(uint param_1)
{
  int iVar1;
  int *piVar2;
  uint uVar3;
  uint *puVar4;
  undefined4 local_38;
  int local_34;
  int local_30;
  undefined4 local_2c;
  undefined auStack_28 [16];
  float local_18;
  
  puVar4 = *(uint **)(param_1 + 0xb8);
  local_38 = DAT_802c2b58;
  local_34 = DAT_802c2b5c;
  local_30 = DAT_802c2b60;
  local_2c = DAT_802c2b64;
  FUN_80006824(param_1,0x72);
  FUN_80057690(param_1);
  if (0 < *(short *)(puVar4 + 2)) {
    *(ushort *)(puVar4 + 2) = *(short *)(puVar4 + 2) - (ushort)DAT_803dc070;
  }
  if (*(char *)((int)puVar4 + 0xb) == '\x01') {
    local_18 = lbl_803E5E78;
    *(undefined *)((int)puVar4 + 0xe) = *(undefined *)(puVar4 + 3);
    iVar1 = ObjHits_GetPriorityHit(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if ((iVar1 != 0) || ((*(short *)(puVar4 + 2) != 0 && (*(short *)(puVar4 + 2) < 0x15)))) {
      *(char *)(puVar4 + 3) = '\x01' - *(char *)(puVar4 + 3);
      if (*(char *)(puVar4 + 3) != '\0') {
        *(undefined2 *)((int)puVar4 + 6) = 1000;
      }
      if (*(short *)(puVar4 + 2) != 0) {
        *(undefined2 *)(puVar4 + 2) = 0;
        DAT_803de868 = '\x03';
        *(undefined2 *)((int)puVar4 + 6) = 300;
        if (*(char *)((int)puVar4 + 0xf) == '\x02') {
          FUN_80017698(0x1d1,1);
        }
      }
    }
    if (((*(char *)(puVar4 + 3) != '\0') && (*(short *)((int)puVar4 + 6) != 0)) &&
       (*(ushort *)((int)puVar4 + 6) = *(short *)((int)puVar4 + 6) - (ushort)DAT_803dc070,
       *(short *)((int)puVar4 + 6) < 1)) {
      *(undefined2 *)((int)puVar4 + 6) = 0;
      *(undefined *)(puVar4 + 3) = 0;
    }
    if (((*(char *)(puVar4 + 3) != '\0') && (*(short *)(puVar4 + 1) < 1)) &&
       (*(char *)((int)puVar4 + 0xd) != '\0')) {
      *(undefined *)((int)puVar4 + 0xd) = 0;
      FUN_80006824(param_1,0x80);
    }
    if (*(char *)(puVar4 + 3) != *(char *)((int)puVar4 + 0xe)) {
      if (*(char *)(puVar4 + 3) == '\0') {
        FUN_8000680c(param_1,0x40);
        (**(code **)(*DAT_803dd6fc + 0x18))(param_1);
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
        if ((*puVar4 != 0xffffffff) && (uVar3 = FUN_80017690(*puVar4), uVar3 != 0)) {
          FUN_80017698(*puVar4,0);
        }
        if ((DAT_803de868 == '\x01') && (*(char *)((int)puVar4 + 0xf) == '\0')) {
          DAT_803de868 = '\0';
        }
        if ((DAT_803de868 == '\x02') && (*(char *)((int)puVar4 + 0xf) == '\x01')) {
          DAT_803de868 = '\0';
        }
        if (((DAT_803de868 == '\x03') && (*(char *)((int)puVar4 + 0xf) == '\x02')) &&
           (uVar3 = FUN_80017690(0x1d5), uVar3 == 0)) {
          FUN_80017698(0x1d1,0);
          DAT_803de868 = '\0';
        }
      }
      else {
        piVar2 = (int *)FUN_80006b14(0x69);
        local_30 = (uint)*(byte *)((int)puVar4 + 0xf) * 2;
        local_34 = local_30 + 0x19d;
        local_30 = local_30 + 0x19e;
        (**(code **)(*piVar2 + 4))(param_1,1,auStack_28,0x10004,0xffffffff,&local_38);
        FUN_80006b0c((undefined *)piVar2);
        iVar1 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x1a3,0,0,0xffffffff,0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < 100);
        if ((*puVar4 != 0xffffffff) && (uVar3 = FUN_80017690(*puVar4), uVar3 == 0)) {
          FUN_80017698(*puVar4,1);
        }
        if (((DAT_803de868 == '\0') && (*(char *)((int)puVar4 + 0xf) == '\0')) &&
           (uVar3 = FUN_80017690(*puVar4), uVar3 != 0)) {
          DAT_803de868 = '\x01';
        }
        if (((DAT_803de868 == '\x01') && (*(char *)((int)puVar4 + 0xf) == '\x01')) &&
           (uVar3 = FUN_80017690(*puVar4), uVar3 != 0)) {
          DAT_803de868 = '\x02';
        }
        if (((DAT_803de868 == '\x02') && (*(char *)((int)puVar4 + 0xf) == '\x02')) &&
           (uVar3 = FUN_80017690(*puVar4), uVar3 != 0)) {
          FUN_80017698(0x1d1,1);
          DAT_803de868 = '\x03';
        }
        *(undefined *)((int)puVar4 + 0xd) = 1;
        *(undefined2 *)(puVar4 + 1) = 1;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: treebird_getExtraSize
 * EN v1.0 Address: 0x801CDA48
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int treebird_getExtraSize(void)
{
  return 0xc;
}
