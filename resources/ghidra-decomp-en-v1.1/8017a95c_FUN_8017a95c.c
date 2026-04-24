// Function: FUN_8017a95c
// Entry: 8017a95c
// Size: 460 bytes

void FUN_8017a95c(uint param_1)

{
  bool bVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined *puVar5;
  char *pcVar6;
  int local_28 [6];
  
  iVar4 = *(int *)(param_1 + 0x4c);
  pcVar6 = *(char **)(param_1 + 0xb8);
  iVar2 = FUN_80036974(param_1,local_28,(int *)0x0,(uint *)0x0);
  if ((iVar2 == 0xe) || (iVar2 == 0xf)) {
    bVar1 = false;
    if ((*(short *)(local_28[0] + 0x46) == 0x14b) &&
       ((*(byte *)(*(int *)(local_28[0] + 0x54) + 0xad) & 2) != 0)) {
      bVar1 = true;
    }
    if (!bVar1) {
      if (*pcVar6 == '\0') {
        puVar5 = *(undefined **)(param_1 + 0xb8);
        if (*(char *)(param_1 + 0xac) == ',') {
          FUN_8000bb38(param_1,0x109);
        }
        else {
          FUN_8000bb38(param_1,0x62);
        }
        puVar3 = (undefined4 *)FUN_800395a4(param_1,0);
        if (puVar3 != (undefined4 *)0x0) {
          *puVar3 = 0x100;
        }
        *puVar5 = 1;
        FUN_800201ac((int)*(short *)(pcVar6 + 2),1);
        if ((*(byte *)(iVar4 + 0x1e) & 3) == 2) {
          *(float *)(pcVar6 + 4) =
               FLOAT_803e439c *
               FLOAT_803e43a0 *
               (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar4 + 0x1a) ^ 0x80000000) -
                      DOUBLE_803e43a8);
        }
      }
      else if ((*(byte *)(iVar4 + 0x1e) & 3) == 1) {
        puVar5 = *(undefined **)(param_1 + 0xb8);
        if (*(char *)(param_1 + 0xac) == ',') {
          FUN_8000bb38(param_1,0x109);
        }
        else {
          FUN_8000bb38(param_1,99);
        }
        puVar3 = (undefined4 *)FUN_800395a4(param_1,0);
        if (puVar3 != (undefined4 *)0x0) {
          *puVar3 = 0;
        }
        *puVar5 = 0;
        FUN_800201ac((int)*(short *)(pcVar6 + 2),0);
      }
    }
  }
  return;
}

