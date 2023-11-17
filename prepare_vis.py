import os
import html
import argparse
import re
import json
import random
import gzip
import pickle as pkl
from subprocess import Popen, PIPE
from multiprocessing import Pool
from tqdm import tqdm
from lexer import Lexer, Token
from collections import defaultdict

def add_options(parser):
    parser.add_argument("--pred", type=str, required=True)
    parser.add_argument("--ref", type=str, required=True)
    parser.add_argument("--bin-mapping", type=str, required=True)
    parser.add_argument("--bins-path", type=str, required=True)
    parser.add_argument("--ida-output-path", type=str, required=True)
    parser.add_argument("--preprocessed-path", type=str, required=True)
    parser.add_argument("--output", type=str, required=True)
    parser.add_argument("--not-train", action="store_true")
    parser.add_argument("--struct", action="store_true")

def get_all_funcs(pred, ref):
    all_funcs = set()
    #assert pred.keys() == ref.keys()
    missing = set(pred.keys()) - set(ref.keys())
    assert len(missing) == 0
    for binary in pred:
        missing = set(pred[binary].keys()) - set(ref[binary].keys())
        assert len(missing) == 0
        #assert pred[binary].keys() == ref[binary].keys()
        for func_name in pred[binary]:
            all_funcs.add((binary, func_name))

    return all_funcs

def eval(pred, ref, funcs):
    count = 0
    correct = 0
    for binary, func_name in funcs:
        for (src_name, src_type), (tgt_name, tgt_type, body_in_train) in zip(pred[binary][func_name], ref[binary][func_name]):
            count += 1
            correct += src_type == tgt_type
    return correct / count

def get_binary_info(func, meta, bins_path):
    binary, func_name = func
    # get disassembler results
    if "path" not in meta:
        return meta
    bin_path = os.path.join(bins_path, meta["path"])
    all_dump = os.popen(f"objdump -d {bin_path}").read().split("\n\n")
    func_dump = [f for f in all_dump if f"<{func_name}>" in f.split("\n")[0]]
    if len(func_dump) >= 1:
        func_dump = func_dump[0]
        meta["objdump"] = func_dump
    else:
        meta["objdump"] = ""

    return meta

def format_code(code):
    # Requires clang-format 
    p = Popen("clang-format-13", stdout=PIPE, stdin=PIPE)
    ret = p.communicate(input=code.encode("utf-8"))[0]
    return ret.decode()

# var = re.compile()

def prepare_highlight_var(code):
    return re.sub(r"@@(\w+)@@", r"e6ff4de4\g<1>4ed4ff6e", code)

# xvar = re.compile()
def highlight_var(code):
    return re.sub(r"e6ff4de4(\w+)4ed4ff6e", lambda m: '<span class="supfact">' + m.group(1) + '</span>', code)

def tokenize_raw_code(raw_code):
    lexer = Lexer(raw_code)
    tokens = []
    for token_type, token in lexer.get_tokens():
        if token_type in Token.Literal:
            token = str(token_type).split('.')[2]

        tokens.append(token)

    return tokens

def get_preprocessed_code(func, pred, ref, preprocessed_path, only_struct=False):
    binary, func_name = func
    with open(os.path.join(preprocessed_path, f"{binary}_{binary}.jsonl")) as f:
        for line in f:
            json_line = json.loads(line)
            if json_line["name"] == func_name:
                varnames = set(name for name in pred[binary][func_name] if not only_struct or ref[binary][func_name][name][1].startswith("struc"))
                code = json_line["code_tokens"]
                code = map(lambda x: x[2:-2] if x.startswith("@@") and x[2:-2] not in varnames else x, code)
                code = " ".join(code)
                return highlight_var(format_code(prepare_highlight_var(html.escape(code))))
    return ""

def get_debug_code(func, ref, ida_output_path, only_struct=False):
    binary, func_name = func
    with gzip.open(os.path.join(ida_output_path, f"{binary}_{binary}.jsonl.gz"), "rt") as f:
        for line in f:
            json_line = json.loads(line)
            if json_line["b"]["n"] == func_name:
                code = tokenize_raw_code(json_line["b"]["c"])
                varnames = set(name[2:-2] for name, typ, _ in ref[binary][func_name].values() if not only_struct or typ.startswith("struc"))
                code = map(lambda x: f"@@{x}@@" if x in varnames else x, code)
                code = " ".join(code)
                return highlight_var(format_code(prepare_highlight_var(html.escape(code))))
    return ""


def main(args):
    func, meta, bins_path, ida_output_path, preprocessed_path, pred, ref, only_struct = args
    info = get_binary_info(func, meta, bins_path)
    info["code_s"] = get_preprocessed_code(func, pred, ref, preprocessed_path, only_struct)
    info["code_t"] = get_debug_code(func, ref, ida_output_path, only_struct)
    info["var"] = []
    binary, func_name = func
    for src_name in pred[binary][func_name]:
        print(f"{binary} {func_name} {src_name}")
        (src_type, src_name_pred), (tgt_name, tgt_type, body_in_train) = pred[binary][func_name][src_name], ref[binary][func_name][src_name]
        info["body_in_train"] = body_in_train
        if tgt_type.startswith("struc") or not only_struct:

            d = {"name": src_name.replace("@", ""), "type": src_type.replace("<unk>", "__unk__"), "pred_name": src_name_pred.replace("<unk>", "__unk__"), "ref_name": tgt_name.replace("@", ""), "ref_type": tgt_type.replace("<unk>", "__unk__")}
            for k in d.keys():
                d[k] = html.escape(d[k])
            info["var"].append(d)

    return info

def sample(all_funcs, num, pred, ref, only_not_in_train=False, only_struct=False):
    if not only_not_in_train and not only_struct:
        return random.sample(all_funcs, num)
    ret = []
    while len(ret) < num:
        binary, func_name = random.sample(all_funcs, 1)[0]
        valid = True
        has_struc = False
        for src_name in pred[binary][func_name]:
            (src_type, src_name_pred), (tgt_name, tgt_type, body_in_train) = pred[binary][func_name][src_name], ref[binary][func_name][src_name]
            if only_not_in_train and body_in_train:
                valid = False
            if tgt_type.startswith("struc"):
                has_struc = True
        if only_struct and not has_struc:
            valid = False
        valid &= os.path.exists(os.path.join("/home/jlacomis/direoutput-new/bins", f"{binary}_{binary}.jsonl.gz"))
        if valid:
            ret.append((binary, func_name))
    return ret


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    add_options(parser)
    args = parser.parse_args()

    pred = json.load(open(args.pred))
    ref = json.load(open(args.ref))
    all_funcs = get_all_funcs(pred, ref)
    sampled_funcs = sample(all_funcs, 100, pred, ref, args.not_train, args.struct)

    bin_mapping = pkl.load(open(args.bin_mapping, "rb"))

    with Pool(processes=1) as pool:
        ret = pool.map(
            main,
            ((func, bin_mapping.get(func[0], defaultdict(str)), args.bins_path, args.ida_output_path, args.preprocessed_path, pred, ref, args.struct) for func in sampled_funcs),
            chunksize=4,
        )
    json.dump(ret, open(args.output, "w"))
