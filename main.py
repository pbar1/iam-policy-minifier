#!/usr/bin/env python3

import argparse
import contextlib
import json
import sys

from policyuniverse.expander_minimizer import minimize_policy

# setup command line arguments
parser = argparse.ArgumentParser("AWS IAM policy minifier")
parser.add_argument("file", type=str, default="-", help="File to read policy doc from")
args = parser.parse_args()

# read the IAM policy to minify
input = sys.stdin if args.file == "-" or args.file == "" else args.file
with sys.stdin if args.file == "-" or args.file == "" else open(args.file) as f:
    policy_json = f.read()
policy = json.loads(policy_json)

# shard the policy statements into groups based on Condition+Effect+ResourceIsStar
groups = dict()
for stmt in policy["Statement"]:
    cond = "" if "Condition" not in stmt.keys() else json.dumps(stmt["Condition"])
    effect = stmt["Effect"]
    rsrc_star = stmt["Resource"] == "*" or stmt["Resource"] == ["*"]

    if cond not in groups.keys():
        groups[cond] = dict()
    if effect not in groups[cond].keys():
        groups[cond][effect] = dict()
    if rsrc_star not in groups[cond][effect].keys():
        groups[cond][effect][rsrc_star] = list()

    groups[cond][effect][rsrc_star].append(stmt)

# merge statements into a union per group and populate a new policy doc with them
grouped_policy = {"Statement": []}
if "Version" in policy.keys():
    grouped_policy["Version"] = policy["Version"]
for _, cond in groups.items():
    for _, effect in cond.items():
        for rsrc_star, stmt_list in effect.items():
            candidate_stmt = stmt_list[0]

            # remove the Sid as it takes up characters
            if "Sid" in candidate_stmt.keys():
                del candidate_stmt["Sid"]

            # merge all action and resource lists, ignoring resource if it is "*"
            for stmt in stmt_list:
                candidate_stmt["Action"].extend(stmt["Action"])
                if not rsrc_star:
                    candidate_stmt["Resource"].extend(stmt["Resource"])
            candidate_stmt["Action"] = list(set(candidate_stmt["Action"]))
            if not rsrc_star:
                candidate_stmt["Resource"] = list(set(candidate_stmt["Resource"]))

            grouped_policy["Statement"].append(candidate_stmt)

with contextlib.redirect_stdout(None):
    with contextlib.redirect_stderr(None):
        min_policy = minimize_policy(grouped_policy)

min_policy_json = json.dumps(min_policy, indent=4, sort_keys=True)
print(min_policy_json)

len_orig = len(json.dumps(policy, separators=(",", ":")))
len_min = len(json.dumps(min_policy, separators=(",", ":")))
print(f"Original: {len_orig}, Minified: {len_min}", file=sys.stderr)
