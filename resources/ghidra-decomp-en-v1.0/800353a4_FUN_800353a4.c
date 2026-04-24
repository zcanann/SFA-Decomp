// Function: FUN_800353a4
// Entry: 800353a4
// Size: 652 bytes

void FUN_800353a4(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,float *param_5)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  short *psVar4;
  undefined8 uVar5;
  int local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined2 local_34;
  undefined2 local_32;
  undefined2 local_30;
  float local_2c;
  float local_28;
  undefined auStack36 [4];
  float local_20 [8];
  
  uVar5 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  local_44 = DAT_802c1b00;
  local_40 = DAT_802c1b04;
  local_3c = DAT_802c1b08;
  local_38 = DAT_802c1b0c;
  if ((param_4 & 0xff) != 0) {
    FUN_8007d6dc((double)*(float *)(iVar1 + 0x98),s_hitstate_frame__f_802cade8);
    iVar2 = FUN_8002fa48((double)*param_5,(double)FLOAT_803db414,iVar1,0);
    if (iVar2 != 0) {
      FUN_8007d6dc(s_reset_803db454);
      param_4 = 0;
    }
  }
  iVar2 = FUN_80036770(iVar1,0,&local_48,0,&local_28,auStack36,local_20);
  if (iVar2 != 0) {
    local_28 = local_28 + FLOAT_803dcdd8;
    local_20[0] = local_20[0] + FLOAT_803dcddc;
    local_2c = FLOAT_803de918;
    local_30 = 0;
    local_32 = 0;
    local_34 = 0;
    local_48 = (int)*(char *)(*(int *)(**(int **)(*(int *)(iVar1 + 0x7c) +
                                                 *(char *)(iVar1 + 0xad) * 4) + 0x58) +
                              local_48 * 0x18 + 0x16);
    if ((int)(param_3 & 0xff) <= local_48) {
      FUN_8007d6dc(s_objHitReact_c__sphere_overflow____802cadfc);
      local_48 = 0;
    }
    psVar4 = (short *)((int)uVar5 + local_48 * 0x14);
    if (iVar2 != 0x11) {
      if ((-1 < *psVar4) && (iVar2 = FUN_8000b5d0(iVar1,(int)*psVar4 & 0xffff), iVar2 == 0)) {
        FUN_8000bb18(iVar1,*psVar4);
      }
      if ((-1 < psVar4[1]) && (iVar2 = FUN_8000b5d0(iVar1,(int)psVar4[1] & 0xffff), iVar2 == 0)) {
        FUN_8000bb18(iVar1,psVar4[1]);
      }
      if (*(char *)(psVar4 + 4) == '\x01') {
        piVar3 = (int *)FUN_80013ec8(0x5a,1);
        (**(code **)(*piVar3 + 4))(0,1,&local_34,0x401,0xffffffff,&local_44);
        if (piVar3 != (int *)0x0) {
          FUN_80013e2c(piVar3);
        }
      }
      else {
        FUN_8009a1dc((double)FLOAT_803de964,iVar1,&local_34,1,0);
      }
    }
    if (((param_4 & 0xff) == 0) && (-1 < psVar4[2])) {
      FUN_80030334((double)FLOAT_803de910,iVar1,(int)psVar4[2],0);
      *param_5 = *(float *)(psVar4 + 6);
      param_4 = 1;
    }
  }
  FUN_80286124(param_4);
  return;
}

