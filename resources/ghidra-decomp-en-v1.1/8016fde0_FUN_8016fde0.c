// Function: FUN_8016fde0
// Entry: 8016fde0
// Size: 1196 bytes

void FUN_8016fde0(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9)

{
  float fVar1;
  uint uVar2;
  undefined uVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  double dVar7;
  double dVar8;
  float local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  puVar6 = *(uint **)(param_9 + 0x5c);
  iVar5 = *(int *)(param_9 + 0x7c);
  iVar4 = *(int *)(param_9 + 0x26);
  if ((*(byte *)(puVar6 + 0x1c) & 8) == 0) {
    puVar6[0xf] = (uint)((float)puVar6[0xf] - FLOAT_803dc074);
    if ((float)puVar6[0xf] < FLOAT_803e3fc8) {
      puVar6[0xf] = (uint)FLOAT_803e3fc8;
    }
    if (param_9[0x23] == 0x83e) {
      if (*puVar6 != 0) {
        FUN_8001dc30((double)FLOAT_803e3fc8,*puVar6,'\0');
      }
      param_9[3] = param_9[3] | 0x4000;
    }
    else {
      if (FLOAT_803e3fc8 == (float)puVar6[0xd]) {
        dVar7 = (double)FUN_800229cc((float *)(param_9 + 0x12));
        puVar6[0xc] = (uint)(float)((double)FLOAT_803e3ff4 / dVar7);
      }
      puVar6[0xd] = (uint)((float)puVar6[0xd] + FLOAT_803dc074);
      if ((float)puVar6[0xc] < (float)puVar6[0xd]) {
        if (*(char *)(iVar4 + 0x19) == '\0') {
          uVar3 = 1;
        }
        else {
          uVar3 = 3;
        }
        FUN_80035eec((int)param_9,0xe,uVar3,0);
      }
      if ((*(byte *)(puVar6 + 0x1c) & 1) == 0) {
        puVar6[9] = *(uint *)(param_9 + 6);
        puVar6[10] = *(uint *)(param_9 + 8);
        puVar6[0xb] = *(uint *)(param_9 + 10);
        *(byte *)(puVar6 + 0x1c) = *(byte *)(puVar6 + 0x1c) | 1;
      }
      if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) != '\0') {
        if (*(char *)(*(int *)(param_9 + 0x2a) + 0xac) == '\x0e') {
          FUN_8000bb38((uint)param_9,0xba);
          (**(code **)(*DAT_803dd718 + 0x10))
                    ((double)*(float *)(param_9 + 6),(double)*(float *)(param_9 + 8),
                     (double)*(float *)(param_9 + 10),(double)FLOAT_803e3ff8,param_9);
          param_2 = (double)*(float *)(param_9 + 8);
          param_3 = (double)*(float *)(param_9 + 10);
          param_4 = (double)FLOAT_803e3fc8;
          (**(code **)(*DAT_803dd718 + 0x14))((double)*(float *)(param_9 + 6),(int)*param_9,2);
        }
        else {
          FUN_8000bb38((uint)param_9,0xb3);
        }
        if (*(char *)((int)puVar6 + 0x71) == '\0') {
          FUN_800998ec(param_9,3);
        }
        else if (*(char *)((int)puVar6 + 0x71) == '\x01') {
          FUN_800998ec(param_9,0);
        }
        else {
          FUN_800998ec(param_9,6);
        }
        puVar6[0xe] = (uint)FLOAT_803e3ff0;
        *(undefined *)(param_9 + 0x1b) = 0;
        if (*puVar6 != 0) {
          FUN_8001f448(*puVar6);
          *puVar6 = 0;
        }
        FUN_8003709c((int)param_9,2);
        FUN_80035ff8((int)param_9);
      }
      fVar1 = FLOAT_803e3fc8;
      if ((float)puVar6[0xe] == FLOAT_803e3fc8) {
        *(undefined4 *)(param_9 + 0x40) = *(undefined4 *)(param_9 + 6);
        *(undefined4 *)(param_9 + 0x42) = *(undefined4 *)(param_9 + 8);
        *(undefined4 *)(param_9 + 0x44) = *(undefined4 *)(param_9 + 10);
        if (iVar5 != 0) {
          if ((*(ushort *)(iVar5 + 0xb0) & 0x40) == 0) {
            FUN_8016f70c((int)param_9,(int)puVar6,iVar5);
          }
          else {
            param_9[0x7c] = 0;
            param_9[0x7d] = 0;
          }
        }
        puVar6[9] = (uint)(*(float *)(param_9 + 0x12) * FLOAT_803dc074 + (float)puVar6[9]);
        puVar6[10] = (uint)(*(float *)(param_9 + 0x14) * FLOAT_803dc074 + (float)puVar6[10]);
        dVar8 = (double)*(float *)(param_9 + 0x16);
        dVar7 = (double)FLOAT_803dc074;
        puVar6[0xb] = (uint)(float)(dVar8 * dVar7 + (double)(float)puVar6[0xb]);
        *(ushort *)((int)puVar6 + 0x46) =
             *(short *)((int)puVar6 + 0x46) + (ushort)DAT_803dc070 * 0x5dc;
        if ((*(byte *)(puVar6 + 0x1c) & 4) != 0) {
          puVar6[10] = (uint)-(FLOAT_803e3ffc * FLOAT_803dc074 - (float)puVar6[10]);
          dVar7 = (double)(float)puVar6[9];
          dVar8 = (double)(float)puVar6[10];
          param_3 = (double)(float)puVar6[0xb];
          iVar4 = FUN_80065a20(dVar7,dVar8,param_3,param_9,local_28,0);
          if (iVar4 == 0) {
            local_28[0] = local_28[0] - FLOAT_803e4000;
            dVar7 = (double)local_28[0];
            if ((dVar7 < (double)FLOAT_803e3fc8) && ((double)FLOAT_803e4004 < dVar7)) {
              puVar6[10] = (uint)(float)((double)(float)puVar6[10] - dVar7);
            }
          }
        }
        *(uint *)(param_9 + 6) = puVar6[9];
        *(uint *)(param_9 + 8) = puVar6[10];
        *(uint *)(param_9 + 10) = puVar6[0xb];
        if (iVar5 != 0) {
          uStack_1c = (uint)*(ushort *)((int)puVar6 + 0x46);
          local_20 = 0x43300000;
          dVar7 = (double)FUN_802945e0();
          *(float *)(param_9 + 6) =
               (float)((double)FLOAT_803e3fcc * dVar7 + (double)*(float *)(param_9 + 6));
          uStack_14 = (uint)*(ushort *)((int)puVar6 + 0x46);
          local_18 = 0x43300000;
          dVar7 = (double)FUN_80294964();
          dVar8 = (double)FLOAT_803e3fcc;
          *(float *)(param_9 + 10) = (float)(dVar8 * dVar7 + (double)*(float *)(param_9 + 10));
        }
        uVar2 = (uint)DAT_803dc070;
        iVar4 = *(int *)(param_9 + 0x7a);
        *(uint *)(param_9 + 0x7a) = iVar4 - uVar2;
        if ((int)(iVar4 - uVar2) < 0) {
          FUN_8002cc9c(dVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
        }
      }
      else {
        *(float *)(param_9 + 0x12) = FLOAT_803e3fc8;
        *(float *)(param_9 + 0x14) = fVar1;
        *(float *)(param_9 + 0x16) = fVar1;
        FUN_80035ea4((int)param_9);
        puVar6[0xe] = (uint)((float)puVar6[0xe] - FLOAT_803dc074);
        if ((double)(float)puVar6[0xe] <= (double)FLOAT_803e3fc8) {
          FUN_8002cc9c((double)(float)puVar6[0xe],param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,(int)param_9);
        }
      }
    }
  }
  return;
}

