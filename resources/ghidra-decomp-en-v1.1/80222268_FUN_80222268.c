// Function: FUN_80222268
// Entry: 80222268
// Size: 340 bytes

/* WARNING: Removing unreachable block (ram,0x80222394) */
/* WARNING: Removing unreachable block (ram,0x80222278) */

uint FUN_80222268(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,float *param_10,float *param_11)

{
  int iVar1;
  uint uVar2;
  double dVar3;
  undefined8 uVar4;
  short asStack_68 [4];
  short asStack_60 [4];
  undefined4 auStack_58 [2];
  float local_50;
  undefined4 local_4c;
  undefined4 local_48;
  float afStack_44 [3];
  float local_38;
  float local_34;
  float local_30;
  
  iVar1 = FUN_8002bac4();
  if (param_9 == iVar1) {
    local_50 = *(float *)(param_9 + 0x24);
    local_4c = *(undefined4 *)(param_9 + 0x28);
    local_48 = *(undefined4 *)(param_9 + 0x2c);
  }
  else {
    FUN_80247eb8((float *)(param_9 + 0xc),(float *)(param_9 + 0x80),&local_50);
  }
  FUN_80247edc((double)FLOAT_803dc078,&local_50,&local_50);
  local_38 = *(float *)(param_9 + 0xc);
  local_34 = FLOAT_803e78f0 + *(float *)(param_9 + 0x10);
  local_30 = *(float *)(param_9 + 0x14);
  iVar1 = 0;
  do {
    dVar3 = FUN_802480e8(&local_38,param_10);
    FUN_80247edc((double)(float)(dVar3 / param_1),&local_50,afStack_44);
    FUN_80247e94((float *)(param_9 + 0xc),afStack_44,&local_38);
    iVar1 = iVar1 + 1;
  } while (iVar1 < 5);
  *param_11 = local_38;
  param_11[1] = local_34;
  param_11[2] = local_30;
  FUN_80012d20(param_10,asStack_68);
  uVar4 = FUN_80012d20(&local_38,asStack_60);
  uVar2 = FUN_800128fc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,asStack_68,
                       asStack_60,auStack_58,(undefined *)0x0,0);
  return (-uVar2 | uVar2) >> 0x1f;
}

