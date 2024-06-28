PINEAPPLE_BASE_DTB += ../qcom/pineapple.dtb ../qcom/pineapple-v2.dtb ../qcom/cliffs.dtb ../qcom/cliffs7.dtb
PINEAPPLE_APQ_BASE_DTB += ../qcom/pineapplep.dtb ../qcom/pineapplep-v2.dtb

OPLUS_PINEAPPLE_BOARDS += waffle-22825-pineapple-overlay.dtbo\
                          waffle-22825-pineapple-overlay-EVB.dtbo\
                          waffle-22825-pineapple-overlay-EVT1.dtbo\
                          waffle-22877-pineapple-overlay.dtbo\
                          waffle-22877-pineapple-overlay-EVB.dtbo\
                          waffle-22877-pineapple-overlay-EVT1.dtbo\
                          pangu-22111-pineapple-overlay.dtbo\
                          pangu-22112-pineapple-overlay.dtbo\
                          enzo-23607-pineapple-overlay.dtbo\
                          huying-23001-pineapple-overlay.dtbo\
                          corvette-23814-pineapple-overlay.dtbo\
                          caihong-23926-pineapple-overlay.dtbo\
                          caihong-23976-pineapple-overlay.dtbo\
                          audi-23803-cliffs-overlay.dtbo\
                          audi-23865-cliffs-overlay.dtbo\
                          bale-23609-cliffs-overlay.dtbo\
                          bale-23622-cliffs-overlay.dtbo\
                          bale-23718-cliffs-overlay.dtbo\
                          bale-24687-cliffs-overlay.dtbo\
                          divo-23631-pineapple-overlay.dtbo\
                          divo-24672-pineapple-overlay.dtbo

dtb-y += $(OPLUS_PINEAPPLE_BOARDS) $(PINEAPPLE_BASE_DTB) $(PINEAPPLE_APQ_BASE_DTB)

always-y	:= $(dtb-y)
subdir-y	:= $(dts-dirs)
clean-files	:= *.dtb *.dtbo
