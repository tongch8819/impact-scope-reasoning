# -------------------
# kernel-exp
# cp data_linux_kernel/train.graph.r20vul.txt kernel-exp/train.graph.txt
# python data_generation.py gen_train_sample -r=Scope_Of_Influences -g=kernel-exp/train.graph.txt -s=kernel-exp/train.pairs.txt
# python DFS.py -s=kernel-exp/paths.all.txt -fs=kernel-exp/paths.threshold.txt -g=kernel-exp/train.graph.txt -t=kernel-exp/train.pairs.txt
# python feature_new.py train -g=kernel-exp/train.graph.txt -t=kernel-exp/train.pairs.txt -p=kernel-exp/abstract_paths.txt.filtered -s=kernel-exp/train.txt
# python model.py -s=kernel-exp/model/ -f=kernel-exp/train.txt.label -p=17

# python graph_construction_new.py -f=data_linux_kernel/nvd_linux_affected_products_20201104.json -s=kernel-exp/test.graph.txt -m=file 2>queryError.log
# python data_generation.py gen_test_vul -s=kernel-exp/test.vul.txt
# python reasoning.py reasoning_all -gf=kernel-exp/test.graph.txt -tf=kernel-exp/test.vul.txt -pf=kernel-exp/abstract_paths.txt.filtered -mf=kernel-exp/model/model_1.pkl -sf=kernel-exp/reasoning.result.txt -t=0.5 -m=model



# -----------------
# kernel-exp-short
# python feature_new.py train -g=kernel-exp-short/train.graph.txt -t=kernel-exp-short/train.pairs.txt -p=kernel-exp-short/abstract_paths.txt.filtered -s=kernel-exp-short/train.txt
python model.py -s=kernel-exp-short/model/ -f=kernel-exp-short/train.txt.label -p=7
