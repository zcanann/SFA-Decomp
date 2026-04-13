// Function: FUN_80098608
// Entry: 80098608
// Size: 1452 bytes

void FUN_80098608(undefined8 param_1,double param_2)

{
  uint uVar1;
  uint uVar2;
  ushort *puVar3;
  int iVar4;
  uint uVar5;
  uint in_r6;
  int in_r7;
  undefined4 uVar6;
  double extraout_f1;
  ulonglong uVar7;
  int local_68;
  int local_64;
  int local_60;
  float local_5c;
  float local_58;
  float local_54 [4];
  float local_44;
  float local_40;
  float local_3c;
  undefined auStack_38 [4];
  undefined2 local_34;
  undefined2 local_32;
  float local_30;
  float local_2c;
  
  uVar7 = FUN_80286834();
  puVar3 = (ushort *)(uVar7 >> 0x20);
  uVar5 = (uint)uVar7;
  uVar2 = (uint)DAT_803dc070;
  if (3 < uVar2) {
    uVar2 = 3;
  }
  local_30 = (float)extraout_f1;
  if (param_2 <= (double)FLOAT_803e0000) {
    param_2 = (double)FLOAT_803e0000;
  }
  local_2c = (float)param_2;
  uVar1 = uVar5 & 0xff;
  if ((uVar7 & 0xff) != 0) {
    if (uVar1 == 3) {
      local_32 = 0x8e;
      for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
        (**(code **)(*DAT_803dd708 + 8))(puVar3,0x7c0,auStack_38,2,0xffffffff,in_r7);
      }
    }
    else if (uVar1 < 3) {
      if (uVar1 == 1) {
        local_32 = 0x159;
        local_34 = 1;
        for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
          (**(code **)(*DAT_803dd708 + 8))(puVar3,0x7be,auStack_38,2,0xffffffff,in_r7);
        }
      }
      else if ((uVar7 & 0xff) != 0) {
        local_32 = 0x159;
        local_34 = 0;
        for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
          (**(code **)(*DAT_803dd708 + 8))(puVar3,0x7be,auStack_38,2,0xffffffff,in_r7);
        }
      }
    }
    else if (uVar1 < 5) {
      uVar6 = 2;
      if (((int)(short)puVar3[3] & 0x40080U) != 0) {
        uVar6 = 0x20000002;
      }
      local_32 = 0xc0e;
      local_34 = 0;
      for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
        (**(code **)(*DAT_803dd708 + 8))(puVar3,0x7eb,auStack_38,uVar6,0xffffffff,in_r7);
      }
    }
  }
  if ((in_r6 & 0xff) != 0) {
    if (in_r7 == 0) {
      FUN_8000edcc((double)(*(float *)(puVar3 + 0xc) - FLOAT_803dda58),
                   (double)*(float *)(puVar3 + 0xe),
                   (double)(*(float *)(puVar3 + 0x10) - FLOAT_803dda5c),(double)FLOAT_803e0004,
                   local_54,&local_58,&local_5c);
    }
    else {
      local_44 = *(float *)(in_r7 + 0xc);
      local_40 = *(float *)(in_r7 + 0x10);
      local_3c = *(float *)(in_r7 + 0x14);
      FUN_80021b8c(puVar3,&local_44);
      FUN_8000edcc((double)((*(float *)(puVar3 + 0xc) + local_44) - FLOAT_803dda58),
                   (double)(*(float *)(puVar3 + 0xe) + local_40),
                   (double)((*(float *)(puVar3 + 0x10) + local_3c) - FLOAT_803dda5c),
                   (double)FLOAT_803e0004,local_54,&local_58,&local_5c);
    }
    FUN_8000ea98((double)local_54[0],(double)local_58,(double)local_5c,&local_60,&local_64,&local_68
                );
    iVar4 = FUN_8006ff74(local_60,local_64,(int)puVar3);
    if (iVar4 < local_68) {
      uVar1 = in_r6 & 0xff;
      if (uVar1 == 2) {
        in_r6 = 5;
      }
      else if (uVar1 < 2) {
        if (uVar1 != 0) {
          in_r6 = 4;
        }
      }
      else if (uVar1 < 4) {
        in_r6 = 6;
      }
    }
    in_r6 = in_r6 & 0xff;
    if (in_r6 == 4) {
      if ((uVar5 & 0xff) == 1) {
        local_32 = 0xc75;
      }
      else {
        local_32 = 0xc74;
      }
      for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
        (**(code **)(*DAT_803dd708 + 8))(puVar3,0x7c4,auStack_38,2,0xffffffff,in_r7);
      }
    }
    else if (in_r6 < 4) {
      if (in_r6 == 2) {
        local_32 = 0x605;
        for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
          (**(code **)(*DAT_803dd708 + 8))(puVar3,0x7bf,auStack_38,2,0xffffffff,in_r7);
        }
      }
      else if (in_r6 < 2) {
        if (in_r6 != 0) {
          if ((uVar5 & 0xff) == 1) {
            local_32 = 0xc75;
          }
          else {
            local_32 = 0xc74;
          }
          for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
            (**(code **)(*DAT_803dd708 + 8))(puVar3,0x7bf,auStack_38,2,0xffffffff,in_r7);
          }
        }
      }
      else {
        if ((uVar5 & 0xff) == 1) {
          local_32 = 0xc75;
        }
        else {
          local_32 = 0xc74;
        }
        for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
          (**(code **)(*DAT_803dd708 + 8))(puVar3,0x7c1,auStack_38,2,0xffffffff,in_r7);
        }
      }
    }
    else if (in_r6 == 6) {
      if ((uVar5 & 0xff) == 1) {
        local_32 = 0xc75;
      }
      else {
        local_32 = 0xc74;
      }
      for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
        (**(code **)(*DAT_803dd708 + 8))(puVar3,0x7c5,auStack_38,2,0xffffffff,in_r7);
      }
    }
    else if (in_r6 < 6) {
      local_32 = 0x605;
      for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
        (**(code **)(*DAT_803dd708 + 8))(puVar3,0x7c4,auStack_38,2,0xffffffff,in_r7);
      }
    }
  }
  FUN_80286880();
  return;
}

