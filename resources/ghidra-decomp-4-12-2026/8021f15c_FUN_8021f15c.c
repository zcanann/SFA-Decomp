// Function: FUN_8021f15c
// Entry: 8021f15c
// Size: 540 bytes

void FUN_8021f15c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 in_r10;
  uint *puVar6;
  undefined8 uVar7;
  float fStack_18;
  undefined4 uStack_14;
  undefined4 auStack_10 [2];
  
  puVar6 = *(uint **)(param_9 + 0xb8);
  puVar4 = &uStack_14;
  puVar5 = auStack_10;
  iVar1 = FUN_80036868(param_9,(undefined4 *)0x0,(int *)0x0,(uint *)0x0,&fStack_18,puVar4,puVar5);
  if ((iVar1 != 0) &&
     ((((*(short *)(puVar6 + 0x9d) == 4 || (((int)*(short *)(puVar6 + 0x9d) - 9U & 0xffff) < 2)) ||
       ((iVar1 != 0xf && (iVar1 != 0xe)))) && (*(short *)(puVar6 + 0x306) != 0)))) {
    FUN_802224e4(param_9,&fStack_18);
    uVar2 = FUN_80022264(0,0);
    FUN_800393e8(param_9,puVar6 + 0xef,(ushort *)(&DAT_803dcf70 + uVar2 * 6),1);
    if ((int)*(short *)(puVar6 + 0x9d) != 3) {
      puVar6[0x30f] = (int)*(short *)(puVar6 + 0x9d);
    }
    if ((*(short *)(puVar6 + 0x9d) == 2) || (*(short *)(puVar6 + 0x9d) == 8)) {
      *(short *)(puVar6 + 0x306) = *(short *)(puVar6 + 0x306) + -1;
      FUN_8009ab54((double)FLOAT_803e77c8,param_9);
      if (*(short *)(puVar6 + 0x306) < 1) {
        FUN_800201ac(0xbf7,0);
        (**(code **)(*DAT_803dd6e8 + 0x60))();
        *(byte *)((int)puVar6 + 0xc49) = *(byte *)((int)puVar6 + 0xc49) & 0xfe;
        uVar7 = FUN_800201ac(0x634,0);
        uVar2 = FUN_8002e144();
        if ((uVar2 & 0xff) != 0) {
          puVar3 = FUN_8002becc(0x2c,0xd4);
          *(undefined *)(puVar3 + 2) = 2;
          *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
          *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 0x10);
          *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
          puVar3[0xd] = 0x675;
          puVar3[0xe] = 0;
          puVar3[0xf] = 0xffff;
          FUN_8002e088(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                       *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),puVar4,
                       puVar5,in_r10);
        }
        *(undefined2 *)(param_9 + 2) = 0;
        *(undefined2 *)(param_9 + 4) = 0;
        *(undefined *)((int)puVar6 + 0x25f) = 0;
        *puVar6 = *puVar6 | 0x1000000;
        FUN_800201ac(0xb48,1);
        (**(code **)(*DAT_803dd6e8 + 0x60))();
      }
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x14))(param_9,puVar6,3);
    }
  }
  return;
}

