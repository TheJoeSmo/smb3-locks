; Original address was $B48A
; World 1 Coin Heaven B?
    .word W103L ; Alternate level layout
    .word W103O ; Alternate object layout
    .byte LEVEL1_SIZE_04 | LEVEL1_YSTART_170
    .byte LEVEL2_BGPAL_00 | LEVEL2_OBJPAL_08 | LEVEL2_XSTART_18
    .byte LEVEL3_TILESET_01 | LEVEL3_VSCROLL_FREE | LEVEL3_PIPENOTEXIT
    .byte 13 & %00011111 | LEVEL4_INITACT_NOTHING
    .byte LEVEL5_BGM_SKY | LEVEL5_TIME_300

    .byte $11, $09, $02, $14, $0A, $02, $03, $1D, $02, $6A, $21, $4F, $09, $35, $0C, $80
    .byte $35, $0E, $80, $36, $0B, $80, $36, $0D, $80, $36, $0F, $80, $06, $1A, $02, $08
    .byte $1C, $02, $0B, $1B, $02, $0F, $1B, $02, $11, $13, $02, $13, $11, $02, $13, $17
    .byte $02, $13, $1B, $02, $35, $10, $80, $35, $15, $80, $35, $17, $80, $35, $19, $80
    .byte $35, $1B, $80, $35, $1F, $80, $36, $11, $80, $36, $16, $80, $36, $18, $80, $36
    .byte $1A, $80, $36, $1E, $80, $06, $24, $02, $09, $25, $02, $0F, $27, $02, $0F, $2D
    .byte $02, $13, $23, $02, $13, $29, $02, $13, $2F, $02, $2B, $27, $0B, $28, $26, $82
    .byte $29, $25, $81, $29, $28, $81, $2A, $24, $81, $2A, $29, $81, $2B, $24, $80, $2B
    .byte $2A, $80, $2C, $24, $81, $2C, $29, $81, $2D, $25, $81, $2D, $28, $81, $2E, $26
    .byte $82, $35, $21, $80, $35, $23, $80, $35, $27, $80, $35, $29, $80, $35, $2B, $80
    .byte $35, $2D, $80, $36, $20, $80, $36, $22, $80, $36, $24, $80, $36, $28, $80, $36
    .byte $2A, $80, $36, $2C, $80, $35, $31, $80, $35, $33, $80, $35, $35, $80, $36, $30
    .byte $80, $36, $32, $80, $36, $34, $80, $36, $36, $80, $79, $00, $21, $3F, $37, $35
    .byte $93, $E3, $12, $38, $FF
