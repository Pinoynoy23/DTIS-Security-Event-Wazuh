#!/usr/bin/env bash
#
# add_fim_dir.sh — Add FIM-monitored directories to Wazuh.
#
# Two-layer filtering model:
#   1. GLOBAL rule (offered once, added at most once): mutes known
#      noisy/non-actionable extensions (.log, .json, .tmp, etc.) across
#      EVERY monitored path, forever. No per-directory setup needed for
#      this baseline layer.
#   2. PER-DIRECTORY rule (optional, chosen each time you add a path):
#      pick specific extensions to alert on for THAT directory only —
#      everything else in that directory is muted, tighter than the
#      global layer. Choose 'all' to skip this and rely on the global
#      layer alone for that directory.
#
# If a path is ALREADY monitored, the script no longer just refuses.
# It looks up whether that path already has a per-directory rule:
#   - If yes, it shows what's currently allowed and lets you ADD more
#     extensions to it — this correctly EDITS the existing rule in place
#     (two separate "only X" rules on the same folder would actually
#     cancel each other out and suppress everything, so this must be an
#     edit, not a second rule).
#   - If no, it offers to create a fresh per-directory rule for it now.
# Either way it skips re-adding the <directories> line (already there)
# and skips the realtime/verify questions (nothing to redo there).
#
# Does NOT use syscheck's `restrict` attribute — on this server
# (Wazuh v4.14.6), `restrict` + realtime FIM was found to silently break
# baseline scanning for the whole directory. Directories are always added
# plain/unrestricted; filtering happens downstream via rules, never by
# stopping syscheck from seeing the files.
#
# Controls at every step:
#   E = Exit script now
#   D = Delete (discard current entry / remove a queued one)
#   R = Return to previous step
#   C = Continue (add another directory, from the confirm screen)
#   S = Save (write everything queued)
#
# Usage: sudo ./add_fim_dir.sh

set -euo pipefail

OSSEC_CONF="/var/ossec/etc/ossec.conf"
LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"
RULE_ID_MIN=190100
RULE_ID_MAX=190199
LATE_SUPPRESSION_GROUP='<group name="late_suppression,">'
GLOBAL_RULE_DESC="Suppressed: global noisy extension filter (auto-managed by add_fim_dir.sh)"

NOISY_BLOCKLIST=(log json tmp bak swp cache lock pid db sqlite csv out gz zip tar)

declare -A EXT_MENU=(
  [1]="py"    [2]="php"   [3]="js"    [4]="ts"    [5]="jsp"
  [6]="asp"   [7]="aspx"  [8]="cgi"   [9]="pl"    [10]="rb"
  [11]="sh"   [12]="bash" [13]="ps1"  [14]="bat"  [15]="cmd"
  [16]="vbs"  [17]="exe"  [18]="dll"  [19]="so"   [20]="jar"
  [21]="war"  [22]="go"   [23]="c"    [24]="cpp"  [25]="java"
  [26]="conf" [27]="yml"  [28]="yaml" [29]="htaccess"
)

declare -a SESSION_PATHS=()
declare -a NEW_LINES=()      # "" = directory already exists, no new <directories> line needed
declare -a SUMMARY=()
declare -a RULE_EXTS=()      # pipe-joined final extension list, "" = no per-dir rule needed
declare -a EDIT_RULE_ID=()   # "" = brand new rule needed; non-empty = edit this existing rule ID
declare -a DELETE_RULE_ID=() # non-empty = remove this existing rule entirely (revert to global-only)
declare -a DELETE_DIRLINE=() # "1" = also remove the <directories> line — stop monitoring entirely

# ---- helpers -----------------------------------------------------------

classify() {
    local v
    v="$(echo "$1" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    case "$v" in
        e|exit|quit)              echo "E" ;;
        d|delete)                 echo "D" ;;
        r|return|back|c|continue) echo "R" ;;
        *)                        echo "" ;;
    esac
}

status() {
    local n=${#SESSION_PATHS[@]}
    [[ $n -gt 0 ]] && echo "(${n} queued, not saved)" || echo "(nothing saved)"
}

SIGINT_DONE=0
on_int() {
    [[ $SIGINT_DONE -eq 1 ]] && exit 130
    SIGINT_DONE=1; trap '' INT
    echo; echo "Exited. $(status)"
    exit 130
}
trap on_int INT

is_noisy() {
    local e="$1" n
    for n in "${NOISY_BLOCKLIST[@]}"; do [[ "$e" == "$n" ]] && return 0; done
    return 1
}

escape_regex() {
    printf '%s' "$1" | sed -e 's/[.[\*^$()+?{}|\\]/\\&/g'
}

# Best-effort real-user detection, robust to `sudo -i` (SUDO_USER survives
# into the root login shell it spawns) and falling back sensibly for nested
# sudo calls or environments with no real login session.
get_added_by() {
    local u=""
    if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        u="$SUDO_USER"
    fi
    if [[ -z "$u" ]]; then
        u="$(logname 2>/dev/null || true)"
        [[ "$u" == "root" ]] && u=""
    fi
    if [[ -z "$u" ]]; then
        u="$(whoami)"
    fi
    echo "$u"
}

# Send a styled summary of this run's changes to Telegram, reusing the same
# bot credentials your custom-telegram integration already uses
# (/etc/wazuh-telegram.env). Silently does nothing if that file, curl, or
# valid credentials aren't present — this is a best-effort convenience
# notification, never something that should block or fail the save itself.
# Call AFTER the restart step, via send_telegram_summary "<restart_status>".
html_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

send_telegram_summary() {
    local restart_status="${1:-not attempted}"
    local env_file="/etc/wazuh-telegram.env"
    [[ -f "$env_file" ]] || return 0
    command -v curl >/dev/null 2>&1 || return 0

    local BOT_TOKEN="" CHAT_ID="" THREAD_ID=""
    local line k v
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "$line" || "$line" == \#* || "$line" != *=* ]] && continue
        k="${line%%=*}"
        v="${line#*=}"
        v="${v%\"}"; v="${v#\"}"
        case "$k" in
            TELEGRAM_BOT_TOKEN) BOT_TOKEN="$v" ;;
            TELEGRAM_CHAT_ID)   CHAT_ID="$v" ;;
            TELEGRAM_THREAD_ID) THREAD_ID="$v" ;;
        esac
    done < "$env_file"
    [[ -n "$BOT_TOKEN" && -n "$CHAT_ID" ]] || return 0

    local host by ts n_changes
    host="$(html_escape "$(hostname 2>/dev/null || echo unknown)")"
    by="$(html_escape "$(get_added_by)")"
    ts="$(date '+%b %d, %Y %H:%M')"
    n_changes=${#SESSION_PATHS[@]}
    [[ ${NEED_GLOBAL_RULE:-0} -eq 1 ]] && n_changes=$((n_changes + 1))

    local DIV="─────────────────"
    local msg=""
    msg+="🛡️ <b>FIM MONITORING UPDATE</b>"$'\n'
    msg+="🖥️ ${host}"$'\n'
    msg+="🔧 add_fim_dir.sh · ${n_changes} change$([ "$n_changes" -eq 1 ] && echo "" || echo "s")"$'\n'
    msg+="📅 ${ts}"$'\n'
    msg+="${DIV}"$'\n'
    msg+="📝 <b>CHANGES</b>"$'\n'

    if [[ ${NEED_GLOBAL_RULE:-0} -eq 1 ]]; then
        msg+="🌐 Added global noise-suppression rule"$'\n'
    fi

    local i p icon detail
    for i in "${!SESSION_PATHS[@]}"; do
        p="$(html_escape "${SESSION_PATHS[$i]}")"
        if [[ "${DELETE_DIRLINE[$i]:-}" == "1" ]]; then
            icon="🗑️ Removed:"
            detail="stopped monitoring entirely"
        elif [[ -n "${DELETE_RULE_ID[$i]:-}" ]]; then
            icon="♻️ Reverted:"
            detail="rule ${DELETE_RULE_ID[$i]} deleted, back to global rule only"
        elif [[ -n "${EDIT_RULE_ID[$i]:-}" ]]; then
            icon="✏️ Updated:"
            detail="now allows $(html_escape "$(printf '.%s ' $(echo "${RULE_EXTS[$i]}" | tr '|' ' '))")(rule ${EDIT_RULE_ID[$i]})"
        elif [[ -n "${NEW_LINES[$i]:-}" ]]; then
            icon="➕ Added:"
            if [[ -n "${RULE_EXTS[$i]:-}" ]]; then
                detail="$(html_escape "$(printf '.%s ' $(echo "${RULE_EXTS[$i]}" | tr '|' ' '))")only"
            else
                detail="global rule only"
            fi
        else
            icon="ℹ️ Changed:"
            detail=""
        fi
        msg+="${icon} <code>${p}</code>"$'\n'
        [[ -n "$detail" ]] && msg+="    ${detail}"$'\n'
    done

    msg+="${DIV}"$'\n'
    msg+="👤 By: <code>${by}</code>"$'\n'
    msg+="✅ Config validated · Restart: ${restart_status}"

    local args=(--data-urlencode "chat_id=${CHAT_ID}" --data-urlencode "text=${msg}" --data-urlencode "parse_mode=HTML")
    [[ -n "$THREAD_ID" ]] && args+=(--data-urlencode "message_thread_id=${THREAD_ID}")

    local resp
    resp="$(curl -s -m 10 "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" "${args[@]}" 2>&1)"
    if echo "$resp" | grep -q '"ok":true'; then
        echo "Telegram notification sent."
    else
        echo "Telegram notification failed (non-fatal)." >&2
    fi
}

path_monitored() {
    local target="${1%/}" block line paths p x
    block=$(awk '/<syscheck>/,/<\/syscheck>/' "$OSSEC_CONF")
    while IFS= read -r line; do
        if [[ "$line" =~ \<directories[^\>]*\>(.*)\</directories\> ]]; then
            paths="${BASH_REMATCH[1]}"
            IFS=',' read -ra p <<< "$paths"
            for x in "${p[@]}"; do [[ "${x%/}" == "$target" ]] && return 0; done
        fi
    done <<< "$block"
    return 1
}

path_queued() {
    local target="${1%/}"
    local p
    for p in "${SESSION_PATHS[@]}"; do [[ "$p" == "$target" ]] && return 0; done
    return 1
}

# Look up whether a path already has a per-directory rule. Echoes
# "ID|ext1|ext2|..." if found, nothing (return 1) if not.
find_existing_rule() {
    local target="${1%/}"
    local lines
    mapfile -t lines < "$LOCAL_RULES"
    local i
    for i in "${!lines[@]}"; do
        if [[ "${lines[$i]}" == *"<description>Suppressed: non-matching extension change in ${target}</description>"* ]]; then
            local field_line="${lines[$((i-1))]}"
            local rule_line="${lines[$((i-3))]}"
            local id="" ext=""
            [[ "$rule_line" =~ id=\"([0-9]+)\" ]] && id="${BASH_REMATCH[1]}"
            [[ "$field_line" =~ \\\.\(([a-zA-Z0-9|]+)\)\$ ]] && ext="${BASH_REMATCH[1]}"
            if [[ -n "$id" && -n "$ext" ]]; then
                echo "${id}|${ext}"
                return 0
            fi
        fi
    done
    return 1
}

splice_out() {
    local i=$1
    unset 'NEW_LINES[i]' 'SUMMARY[i]' 'SESSION_PATHS[i]' 'RULE_EXTS[i]' 'EDIT_RULE_ID[i]' 'DELETE_RULE_ID[i]' 'DELETE_DIRLINE[i]'
    NEW_LINES=("${NEW_LINES[@]}"); SUMMARY=("${SUMMARY[@]}")
    SESSION_PATHS=("${SESSION_PATHS[@]}"); RULE_EXTS=("${RULE_EXTS[@]}")
    EDIT_RULE_ID=("${EDIT_RULE_ID[@]}"); DELETE_RULE_ID=("${DELETE_RULE_ID[@]}")
    DELETE_DIRLINE=("${DELETE_DIRLINE[@]}")
}

manage_delete() {
    local have_current=0
    local i j r tok
    [[ -n "$CUR_EDIT_ID" && -n "$CUR_PATH" ]] && have_current=1
    local total=${#SESSION_PATHS[@]}
    if [[ $total -eq 0 && $have_current -eq 0 ]]; then
        echo "Nothing queued to delete."
        STEP=1
        return
    fi

    if [[ $total -gt 0 ]]; then
        echo "Queued:"
        for i in "${!SUMMARY[@]}"; do printf "%2d) %s\n" "$((i+1))" "${SUMMARY[$i]}"; done
    fi
    local current_num=-1
    if [[ $have_current -eq 1 ]]; then
        current_num=$((total+1))
        printf "%2d) %s -> %s(currently editing, not yet added)\n" "$current_num" "$CUR_PATH" "$(printf '.%s ' "${CUR_EXISTING_EXTS[@]}")"
    fi

    read -rp "Delete #: " NUM
    if ! [[ "$NUM" =~ ^[0-9]+$ ]]; then
        echo "Invalid #."
        STEP=1
        return
    fi

    if [[ $have_current -eq 1 && $NUM -eq $current_num ]]; then
        local CUREXT=("${CUR_EXISTING_EXTS[@]}")
        echo "${CUR_PATH} — currently: $(printf '.%s ' "${CUREXT[@]}")"
        for j in "${!CUREXT[@]}"; do printf "%2d) .%s\n" "$((j+1))" "${CUREXT[$j]}"; done
        read -rp "[A]ll (delete entire rule ${CUR_EDIT_ID}, revert to global-only) or extension #(s) to remove > " SUB
        local LOWSUB
        LOWSUB="$(echo "$SUB" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
        if [[ "$LOWSUB" == "a" || "$LOWSUB" == "all" ]]; then
            NEW_LINES+=(""); SESSION_PATHS+=("$CUR_PATH"); RULE_EXTS+=("")
            EDIT_RULE_ID+=(""); DELETE_RULE_ID+=("$CUR_EDIT_ID"); DELETE_DIRLINE+=("")
            SUMMARY+=("${CUR_PATH} -> DELETE rule ${CUR_EDIT_ID} entirely, revert to global rule only")
            echo "Queued: rule ${CUR_EDIT_ID} will be deleted entirely."
            CUR_PATH=""; CUR_EDIT_ID=""; CUR_EXISTING_EXTS=(); CUR_EXTS=()
            STEP=1
        else
            local REMOVE_IDX=()
            for tok in $SUB; do
                [[ "$tok" =~ ^[0-9]+$ ]] && (( tok >= 1 && tok <= ${#CUREXT[@]} )) && REMOVE_IDX+=("$tok")
            done
            if [[ ${#REMOVE_IDX[@]} -eq 0 ]]; then
                echo "Invalid selection."
            else
                local NEWLIST=()
                for j in "${!CUREXT[@]}"; do
                    local keep=1
                    for r in "${REMOVE_IDX[@]}"; do [[ $((r-1)) -eq $j ]] && keep=0; done
                    [[ $keep -eq 1 ]] && NEWLIST+=("${CUREXT[$j]}")
                done
                if [[ ${#NEWLIST[@]} -eq 0 ]]; then
                    echo "Can't remove all this way — would leave the rule with nothing allowed."
                    echo "Use [A]ll instead to delete the whole rule."
                else
                    CUR_EXISTING_EXTS=("${NEWLIST[@]}")
                    echo "Now allows: $(printf '.%s ' "${CUR_EXISTING_EXTS[@]}")— still editing, not yet added."
                fi
            fi
            STEP=2
        fi
        return
    fi

    if ! (( NUM >= 1 && NUM <= total )); then
        echo "Invalid #."
        STEP=1
        return
    fi
    STEP=1
    local i=$((NUM-1))
    if [[ -n "${RULE_EXTS[$i]}" ]]; then
        local CUREXT
        IFS='|' read -ra CUREXT <<< "${RULE_EXTS[$i]}"
        echo "${SESSION_PATHS[$i]} — currently: $(printf '.%s ' "${CUREXT[@]}")"
        for j in "${!CUREXT[@]}"; do printf "%2d) .%s\n" "$((j+1))" "${CUREXT[$j]}"; done
        read -rp "[A]ll (delete entire path) or extension #(s) to remove > " SUB
        local LOWSUB
        LOWSUB="$(echo "$SUB" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
        if [[ "$LOWSUB" == "a" || "$LOWSUB" == "all" ]]; then
            echo "Deleted: ${SUMMARY[$i]}"
            splice_out "$i"
        else
            local REMOVE_IDX=()
            for tok in $SUB; do
                [[ "$tok" =~ ^[0-9]+$ ]] && (( tok >= 1 && tok <= ${#CUREXT[@]} )) && REMOVE_IDX+=("$tok")
            done
            if [[ ${#REMOVE_IDX[@]} -eq 0 ]]; then
                echo "Invalid selection."
            else
                local NEWLIST=()
                for j in "${!CUREXT[@]}"; do
                    local keep=1
                    for r in "${REMOVE_IDX[@]}"; do [[ $((r-1)) -eq $j ]] && keep=0; done
                    [[ $keep -eq 1 ]] && NEWLIST+=("${CUREXT[$j]}")
                done
                if [[ ${#NEWLIST[@]} -eq 0 ]]; then
                    if [[ -n "${EDIT_RULE_ID[$i]}" ]]; then
                        echo "Can't remove all — would leave the rule with nothing allowed."
                        echo "Use [A]ll instead if you want to drop this path entirely."
                    else
                        RULE_EXTS[$i]=""
                        SUMMARY[$i]="${SESSION_PATHS[$i]} -> global rule only"
                        echo "Removed all per-directory filtering — will rely on global rule only."
                    fi
                else
                    RULE_EXTS[$i]=$(IFS='|'; echo "${NEWLIST[*]}")
                    local TAG=" (new per-directory rule)"
                    [[ -n "${EDIT_RULE_ID[$i]}" ]] && TAG=" (updating rule ${EDIT_RULE_ID[$i]})"
                    SUMMARY[$i]="${SESSION_PATHS[$i]} -> $(printf '.%s ' "${NEWLIST[@]}")${TAG}"
                    echo "Updated: ${SUMMARY[$i]}"
                fi
            fi
        fi
    else
        echo "Deleted: ${SUMMARY[$i]}"
        splice_out "$i"
    fi
}

# Populates ALL_MON_PATHS with every path from a single-path <directories>
# line in ossec.conf, ALL_MON_TS with a matching add-timestamp, and
# ALL_MON_BY with who added it — all read from a preceding
# "<!-- add_fim_dir.sh added TIMESTAMP by USER: PATH -->" comment, if one
# exists ("" for paths added before this feature existed, or by hand).
# Multi-path comma-grouped lines (e.g. the built-in "/etc,/usr/bin,/usr/sbin")
# are skipped — this tool only ever creates single-path lines, so those are
# the only ones safe to manage here.
list_all_monitored() {
    ALL_MON_PATHS=()
    ALL_MON_TS=()
    ALL_MON_BY=()
    local block line paths prev_line ts_val by_val
    block=$(awk '/<syscheck>/,/<\/syscheck>/' "$OSSEC_CONF")
    prev_line=""
    while IFS= read -r line; do
        if [[ "$line" =~ \<directories[^\>]*\>(.*)\</directories\> ]]; then
            paths="${BASH_REMATCH[1]}"
            if [[ "$paths" != *,* ]]; then
                ts_val=""
                by_val=""
                if [[ "$prev_line" =~ \<!--\ add_fim_dir\.sh\ added\ ([0-9-]+\ [0-9:]+)\ by\ ([a-zA-Z0-9_.-]+):\ (.*)\ --\> ]]; then
                    if [[ "${BASH_REMATCH[3]}" == "${paths%/}" ]]; then
                        ts_val="${BASH_REMATCH[1]}"
                        by_val="${BASH_REMATCH[2]}"
                    fi
                fi
                ALL_MON_PATHS+=("${paths%/}")
                ALL_MON_TS+=("$ts_val")
                ALL_MON_BY+=("$by_val")
            fi
        fi
        prev_line="$line"
    done <<< "$block"
}

# Browse everything currently monitored (reading live from disk), with the
# ability to queue a deletion (partial extension trim, full rule removal,
# or fully unmonitoring the path) and to jump into the Add workflow.
# Sets GOTO_ADD=1 if the user chooses to add more paths.
GOTO_ADD=0
view_monitored_menu() {
    while true; do
        list_all_monitored
        echo "========================================"
        echo "Monitored paths:"
        if [[ ${#ALL_MON_PATHS[@]} -eq 0 ]]; then
            echo "  (none found)"
        fi
        declare -a VIEW_ID=() VIEW_EXT=()
        local i p found tag j r tok ts_disp by_disp
        for i in "${!ALL_MON_PATHS[@]}"; do
            p="${ALL_MON_PATHS[$i]}"
            found="$(find_existing_rule "$p" || true)"
            if [[ -n "$found" ]]; then
                VIEW_ID[$i]="${found%%|*}"
                VIEW_EXT[$i]="${found#*|}"
            else
                VIEW_ID[$i]=""
                VIEW_EXT[$i]=""
            fi
            tag=""
            path_queued "$p" && tag="  [pending change queued this session]"
            ts_disp="${ALL_MON_TS[$i]:-unknown}"
            by_disp="${ALL_MON_BY[$i]:-unknown}"
            if [[ -n "${VIEW_EXT[$i]}" ]]; then
                printf "%2d) [added %s by %s]  - %s -> %s%s\n" "$((i+1))" "$ts_disp" "$by_disp" "$p" "$(printf '.%s ' $(echo "${VIEW_EXT[$i]}" | tr '|' ' '))" "$tag"
            else
                printf "%2d) [added %s by %s]  - %s -> global rule only%s\n" "$((i+1))" "$ts_disp" "$by_disp" "$p" "$tag"
            fi
        done
        echo "----------------------------------------"
        local hint="[A]dd more paths  [D]elete #  [E]xit to main menu"
        if [[ ${#SESSION_PATHS[@]} -gt 0 ]]; then
            hint="[A]dd more paths  [D]elete #  [S]ave  [E]xit to main menu"
        fi
        read -rp "${hint} > " IN
        local c v SELNUM
        c="$(classify "$IN")"
        v="$(echo "$IN" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
        if [[ -z "$v" ]]; then continue; fi
        if [[ "$v" == "e" || "$v" == "exit" ]]; then return; fi
        if [[ "$v" == "a" || "$v" == "add" ]]; then GOTO_ADD=1; return; fi
        if [[ "$v" == "s" || "$v" == "save" ]]; then
            if [[ ${#SESSION_PATHS[@]} -eq 0 ]]; then
                echo "Nothing queued yet — nothing to save."
                continue
            fi
            perform_save
        fi
        if [[ "$c" == "D" ]]; then
            read -rp "Delete #: " SELNUM
        elif [[ "$IN" =~ ^[0-9]+$ ]]; then
            SELNUM="$IN"
        else
            echo "Invalid selection."
            continue
        fi
        if ! [[ "$SELNUM" =~ ^[0-9]+$ ]] || (( SELNUM < 1 || SELNUM > ${#ALL_MON_PATHS[@]} )); then
            echo "Invalid selection."
            continue
        fi
        i=$((SELNUM-1))
        p="${ALL_MON_PATHS[$i]}"
        if path_queued "$p"; then
            echo "This path already has a pending change queued this session."
            echo "Exit to the main menu and Save first, or manage it from there."
            continue
        fi
        if [[ -n "${VIEW_ID[$i]}" ]]; then
            local CUREXT
            IFS='|' read -ra CUREXT <<< "${VIEW_EXT[$i]}"
            echo "${p} — currently: $(printf '.%s ' "${CUREXT[@]}")"
            for j in "${!CUREXT[@]}"; do printf "%2d) .%s\n" "$((j+1))" "${CUREXT[$j]}"; done
            read -rp "[A]ll (stop monitoring this path entirely) or extension #(s) to remove from its filter > " SUB
            local LOWSUB
            LOWSUB="$(echo "$SUB" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
            if [[ "$LOWSUB" == "a" || "$LOWSUB" == "all" ]]; then
                NEW_LINES+=(""); SESSION_PATHS+=("$p"); RULE_EXTS+=("")
                EDIT_RULE_ID+=(""); DELETE_RULE_ID+=("${VIEW_ID[$i]}"); DELETE_DIRLINE+=("1")
                SUMMARY+=("${p} -> STOP MONITORING entirely (removes directory + rule ${VIEW_ID[$i]})")
                echo "Queued: will stop monitoring ${p} entirely."
            else
                local REMOVE_IDX=()
                for tok in $SUB; do
                    [[ "$tok" =~ ^[0-9]+$ ]] && (( tok >= 1 && tok <= ${#CUREXT[@]} )) && REMOVE_IDX+=("$tok")
                done
                if [[ ${#REMOVE_IDX[@]} -eq 0 ]]; then
                    echo "Invalid selection."
                else
                    local NEWLIST=()
                    for j in "${!CUREXT[@]}"; do
                        local keep=1
                        for r in "${REMOVE_IDX[@]}"; do [[ $((r-1)) -eq $j ]] && keep=0; done
                        [[ $keep -eq 1 ]] && NEWLIST+=("${CUREXT[$j]}")
                    done
                    if [[ ${#NEWLIST[@]} -eq 0 ]]; then
                        echo "Can't remove all this way — would leave the rule with nothing allowed."
                        echo "Use [A]ll instead to stop monitoring this path."
                    else
                        local newext
                        newext=$(IFS='|'; echo "${NEWLIST[*]}")
                        NEW_LINES+=(""); SESSION_PATHS+=("$p"); RULE_EXTS+=("$newext")
                        EDIT_RULE_ID+=("${VIEW_ID[$i]}"); DELETE_RULE_ID+=(""); DELETE_DIRLINE+=("")
                        SUMMARY+=("${p} -> $(printf '.%s ' "${NEWLIST[@]}")(updating rule ${VIEW_ID[$i]})")
                        echo "Queued: rule ${VIEW_ID[$i]} will be updated."
                    fi
                fi
            fi
        else
            read -rp "${p} relies on global rule only. [A]ll = stop monitoring entirely, or [C]ancel > " SUB
            local LOWSUB
            LOWSUB="$(echo "$SUB" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
            if [[ "$LOWSUB" == "a" || "$LOWSUB" == "all" ]]; then
                NEW_LINES+=(""); SESSION_PATHS+=("$p"); RULE_EXTS+=("")
                EDIT_RULE_ID+=(""); DELETE_RULE_ID+=(""); DELETE_DIRLINE+=("1")
                SUMMARY+=("${p} -> STOP MONITORING entirely")
                echo "Queued: will stop monitoring ${p} entirely."
            else
                echo "Cancelled."
            fi
        fi
    done
}

if [[ $EUID -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi
if [[ ! -f "$OSSEC_CONF" ]]; then echo "ERROR: $OSSEC_CONF not found." >&2; exit 1; fi
if [[ ! -f "$LOCAL_RULES" ]]; then echo "ERROR: $LOCAL_RULES not found." >&2; exit 1; fi

NEED_GLOBAL_RULE=0
GLOBAL_RULE_ASKED=0
ask_global_rule_once() {
    [[ $GLOBAL_RULE_ASKED -eq 1 ]] && return
    GLOBAL_RULE_ASKED=1
    if grep -qF "$GLOBAL_RULE_DESC" "$LOCAL_RULES"; then
        echo "Global noise-suppression rule already present — noisy extensions"
        echo "(${NOISY_BLOCKLIST[*]}) are already muted everywhere."
    else
        echo "No global noise-suppression rule found yet."
        echo "It would mute these extensions on EVERY monitored path, everywhere:"
        echo "  ${NOISY_BLOCKLIST[*]}"
        echo "Everything else keeps alerting normally unless you filter it per-directory below."
        read -rp "Add it now, as part of this run's save? y/n > " ADDGLOBAL
        if [[ "$ADDGLOBAL" =~ ^[Yy] ]]; then
            NEED_GLOBAL_RULE=1
            echo "Queued — will be included when you save."
        else
            echo "Skipping. You'll be asked again next run."
        fi
    fi
}

perform_save() {
if [[ ${#SESSION_PATHS[@]} -eq 0 && $NEED_GLOBAL_RULE -eq 0 ]]; then
  echo "Nothing to write."; exit 0
fi

# ---- build rule blocks: global (optional) + new per-directory rules -------
# (Edits to EXISTING rules are applied separately, in-place, at write time —
# they don't need a new ID or a new block.)
declare -a RULE_BLOCKS=()
NEED_ANY_RULE=$NEED_GLOBAL_RULE
for i in "${!RULE_EXTS[@]}"; do
  [[ -n "${RULE_EXTS[$i]}" && -z "${EDIT_RULE_ID[$i]}" ]] && NEED_ANY_RULE=1
done
NEED_ANY_EDIT=0
for id in "${EDIT_RULE_ID[@]}"; do [[ -n "$id" ]] && NEED_ANY_EDIT=1; done
NEED_ANY_DELETE=0
for id in "${DELETE_RULE_ID[@]}"; do [[ -n "$id" ]] && NEED_ANY_DELETE=1; done

if [[ $NEED_ANY_RULE -eq 1 || $NEED_ANY_EDIT -eq 1 || $NEED_ANY_DELETE -eq 1 ]]; then
  if ! grep -qF "$LATE_SUPPRESSION_GROUP" "$LOCAL_RULES"; then
    echo "ERROR: expected group ${LATE_SUPPRESSION_GROUP} not found in $LOCAL_RULES." >&2
    echo "Refusing to guess where to insert — no changes made." >&2
    exit 1
  fi
fi

if [[ $NEED_ANY_RULE -eq 1 ]]; then
  # NOTE: matches ONLY 190xxx, not a looser "19+4 digits" pattern — this
  # file also has 199xxx registry rules which would otherwise falsely
  # inflate the max and wrongly report the range as exhausted.
  MAX_ID=$((RULE_ID_MIN - 1))
  while IFS= read -r found; do
    [[ "$found" =~ ^[0-9]+$ ]] && (( found > MAX_ID )) && MAX_ID=$found
  done < <(grep -oE '<rule id="190[0-9]{3}"' "$LOCAL_RULES" | grep -oE '190[0-9]{3}')
  NEXT_ID=$((MAX_ID + 1))
  [[ $NEXT_ID -lt $RULE_ID_MIN ]] && NEXT_ID=$RULE_ID_MIN

  if [[ $NEED_GLOBAL_RULE -eq 1 ]]; then
    if [[ $NEXT_ID -gt $RULE_ID_MAX ]]; then
      echo "ERROR: rule ID range ${RULE_ID_MIN}-${RULE_ID_MAX} is exhausted." >&2
      exit 1
    fi
    EXT_JOINED=$(IFS='|'; echo "${NOISY_BLOCKLIST[*]}")
    GLOBAL_RULE_BLOCK="  <rule id=\"${NEXT_ID}\" level=\"0\">
    <if_group>syscheck</if_group>
    <field name=\"file\" type=\"pcre2\">\\.(${EXT_JOINED})\$</field>
    <description>${GLOBAL_RULE_DESC}</description>
  </rule>"
    RULE_BLOCKS+=("$GLOBAL_RULE_BLOCK")
    NEXT_ID=$((NEXT_ID + 1))
  fi

  for i in "${!RULE_EXTS[@]}"; do
    [[ -z "${RULE_EXTS[$i]}" ]] && continue
    [[ -n "${EDIT_RULE_ID[$i]}" ]] && continue   # edits handled separately below
    if [[ $NEXT_ID -gt $RULE_ID_MAX ]]; then
      echo "ERROR: rule ID range ${RULE_ID_MIN}-${RULE_ID_MAX} is exhausted." >&2
      exit 1
    fi
    ESC_PATH="$(escape_regex "${SESSION_PATHS[$i]}")"
    RULE_BLOCK="  <rule id=\"${NEXT_ID}\" level=\"0\">
    <if_group>syscheck</if_group>
    <field name=\"file\" type=\"pcre2\">^${ESC_PATH}/(?!.*\\.(${RULE_EXTS[$i]})\$).*\$</field>
    <description>Suppressed: non-matching extension change in ${SESSION_PATHS[$i]}</description>
  </rule>"
    RULE_BLOCKS+=("$RULE_BLOCK")
    SUMMARY[$i]="${SUMMARY[$i]}  [rule ${NEXT_ID}]"
    NEXT_ID=$((NEXT_ID + 1))
  done
fi

# ---- final review before writing anything ----------------------------------
echo "========================================"
echo "About to write:"
for s in "${SUMMARY[@]}"; do echo "  - $s"; done
if [[ ${#RULE_BLOCKS[@]} -gt 0 ]]; then
  echo
  echo "New rule(s) for $LOCAL_RULES:"
  for r in "${RULE_BLOCKS[@]}"; do echo "$r"; echo; done
fi
if [[ $NEED_ANY_EDIT -eq 1 ]]; then
  echo "Existing rule(s) to update:"
  for i in "${!EDIT_RULE_ID[@]}"; do
    [[ -n "${EDIT_RULE_ID[$i]}" ]] && echo "  - rule ${EDIT_RULE_ID[$i]} -> allow: ${RULE_EXTS[$i]//|/, }"
  done
fi
if [[ $NEED_ANY_DELETE -eq 1 ]]; then
  echo "Existing rule(s) to DELETE entirely:"
  for i in "${!DELETE_RULE_ID[@]}"; do
    [[ -n "${DELETE_RULE_ID[$i]}" ]] && echo "  - rule ${DELETE_RULE_ID[$i]} (${SESSION_PATHS[$i]} reverts to global rule only)"
  done
fi
read -rp "Write now? y/n > " FINAL_CONFIRM
[[ "$FINAL_CONFIRM" =~ ^[Yy] ]] || { echo "Cancelled. Nothing written."; exit 0; }

rollback_all() {
  [[ -n "$OSSEC_BACKUP" ]] && cp "$OSSEC_BACKUP" "$OSSEC_CONF"
  [[ -n "$RULES_BACKUP" ]] && cp "$RULES_BACKUP" "$LOCAL_RULES"
  echo "Rolled back to pre-write state." >&2
}

# ---- STAGE 1: build candidate ossec.conf (adds + removals) -----------------
declare -a REAL_NEW_LINES=()
for line in "${NEW_LINES[@]}"; do [[ -n "$line" ]] && REAL_NEW_LINES+=("$line"); done

declare -A REMOVE_PATH_SET=()
for i in "${!DELETE_DIRLINE[@]}"; do
  [[ "${DELETE_DIRLINE[$i]}" == "1" ]] && REMOVE_PATH_SET["${SESSION_PATHS[$i]}"]=1
done

conf_line_is_removable() {
  local ln="$1"
  if [[ "$ln" =~ \<directories[^\>]*\>(.*)\</directories\> ]]; then
    local pp="${BASH_REMATCH[1]}"
    [[ "$pp" != *,* && -n "${REMOVE_PATH_SET[${pp%/}]:-}" ]] && return 0
  fi
  if [[ "$ln" =~ \<!--\ add_fim_dir\.sh\ added\ [0-9-]+\ [0-9:]+\ by\ [a-zA-Z0-9_.-]+:\ (.*)\ --\> ]]; then
    [[ -n "${REMOVE_PATH_SET[${BASH_REMATCH[1]}]:-}" ]] && return 0
  fi
  return 1
}

if [[ ${#REAL_NEW_LINES[@]} -gt 0 || ${#REMOVE_PATH_SET[@]} -gt 0 ]]; then
  mapfile -t CONF_LINES < "$OSSEC_CONF"
  IDX=-1
  for i in "${!CONF_LINES[@]}"; do
    [[ "${CONF_LINES[$i]}" == *"</syscheck>"* ]] && { IDX=$i; break; }
  done
  if [[ $IDX -lt 0 ]]; then
    echo "ERROR: </syscheck> not found in $OSSEC_CONF. Nothing written." >&2
    exit 1
  fi
  {
    for ((i=0; i<IDX; i++)); do
      conf_line_is_removable "${CONF_LINES[$i]}" || printf '%s\n' "${CONF_LINES[$i]}"
    done
    for line in "${REAL_NEW_LINES[@]}"; do printf '%s\n' "$line"; done
    for ((i=IDX; i<${#CONF_LINES[@]}; i++)); do
      conf_line_is_removable "${CONF_LINES[$i]}" || printf '%s\n' "${CONF_LINES[$i]}"
    done
  } > "${OSSEC_CONF}.tmp"
  if [[ ${#REAL_NEW_LINES[@]} -gt 0 ]] && ! grep -qF "${REAL_NEW_LINES[0]}" "${OSSEC_CONF}.tmp"; then
    echo "ERROR: failed to build ossec.conf candidate. Nothing written." >&2
    rm -f "${OSSEC_CONF}.tmp"
    exit 1
  fi
  for rp in "${!REMOVE_PATH_SET[@]}"; do
    if grep -qF ">${rp}<" "${OSSEC_CONF}.tmp"; then
      echo "ERROR: failed to remove directory line for ${rp}. Nothing written." >&2
      rm -f "${OSSEC_CONF}.tmp"
      exit 1
    fi
  done
fi

# ---- STAGE 2: build candidate local_rules.xml (deletes + edits + new blocks) --
if [[ ${#RULE_BLOCKS[@]} -gt 0 || $NEED_ANY_EDIT -eq 1 || $NEED_ANY_DELETE -eq 1 ]]; then
  mapfile -t RULE_LINES < "$LOCAL_RULES"

  # Remove rule blocks marked for full deletion FIRST, so the edit lookups
  # below (which search fresh by ID each time) see the post-deletion state.
  declare -A SEEN_DELETE=()
  for did in "${DELETE_RULE_ID[@]}"; do
    [[ -z "$did" ]] && continue
    [[ -n "${SEEN_DELETE[$did]:-}" ]] && continue
    SEEN_DELETE[$did]=1
    START_IDX=-1
    for j in "${!RULE_LINES[@]}"; do
      if [[ "${RULE_LINES[$j]}" == *"<rule id=\"${did}\""* ]]; then
        START_IDX=$j
        break
      fi
    done
    if [[ $START_IDX -lt 0 ]]; then
      echo "ERROR: could not locate rule id ${did} to delete. Nothing written." >&2
      rm -f "${OSSEC_CONF}.tmp" 2>/dev/null
      exit 1
    fi
    END_IDX=-1
    for ((j=START_IDX; j<${#RULE_LINES[@]}; j++)); do
      if [[ "${RULE_LINES[$j]}" == *"</rule>"* ]]; then
        END_IDX=$j
        break
      fi
    done
    if [[ $END_IDX -lt 0 ]]; then
      echo "ERROR: malformed rule block for id ${did} (no closing </rule>). Nothing written." >&2
      rm -f "${OSSEC_CONF}.tmp" 2>/dev/null
      exit 1
    fi
    NEWRULE_LINES=()
    for ((j=0; j<START_IDX; j++)); do NEWRULE_LINES+=("${RULE_LINES[$j]}"); done
    for ((j=END_IDX+1; j<${#RULE_LINES[@]}; j++)); do NEWRULE_LINES+=("${RULE_LINES[$j]}"); done
    RULE_LINES=("${NEWRULE_LINES[@]}")
  done

  # Apply in-place edits to existing rules next.
  for i in "${!EDIT_RULE_ID[@]}"; do
    eid="${EDIT_RULE_ID[$i]}"
    [[ -z "$eid" ]] && continue
    FIELD_IDX=-1
    for j in "${!RULE_LINES[@]}"; do
      if [[ "${RULE_LINES[$j]}" == *"<rule id=\"${eid}\""* ]]; then
        FIELD_IDX=$((j+2))
        break
      fi
    done
    if [[ $FIELD_IDX -lt 0 ]]; then
      echo "ERROR: could not locate rule id ${eid} to edit. Nothing written." >&2
      rm -f "${OSSEC_CONF}.tmp" 2>/dev/null
      exit 1
    fi
    ESC_PATH="$(escape_regex "${SESSION_PATHS[$i]}")"
    RULE_LINES[$FIELD_IDX]="    <field name=\"file\" type=\"pcre2\">^${ESC_PATH}/(?!.*\\.(${RULE_EXTS[$i]})\$).*\$</field>"
  done

  if [[ ${#RULE_BLOCKS[@]} -gt 0 ]]; then
    GROUP_IDX=-1
    for i in "${!RULE_LINES[@]}"; do
      [[ "${RULE_LINES[$i]}" == *"$LATE_SUPPRESSION_GROUP"* ]] && { GROUP_IDX=$i; break; }
    done
    CLOSE_IDX=-1
    if [[ $GROUP_IDX -ge 0 ]]; then
      for ((i=GROUP_IDX+1; i<${#RULE_LINES[@]}; i++)); do
        [[ "${RULE_LINES[$i]}" == *"</group>"* ]] && { CLOSE_IDX=$i; break; }
      done
    fi
    if [[ $CLOSE_IDX -lt 0 ]]; then
      echo "ERROR: could not find closing </group> for late_suppression block. Nothing written." >&2
      rm -f "${OSSEC_CONF}.tmp" 2>/dev/null
      exit 1
    fi
    {
      for ((i=0; i<CLOSE_IDX; i++)); do printf '%s\n' "${RULE_LINES[$i]}"; done
      for r in "${RULE_BLOCKS[@]}"; do printf '%s\n\n' "$r"; done
      for ((i=CLOSE_IDX; i<${#RULE_LINES[@]}; i++)); do printf '%s\n' "${RULE_LINES[$i]}"; done
    } > "${LOCAL_RULES}.tmp"
  else
    printf '%s\n' "${RULE_LINES[@]}" > "${LOCAL_RULES}.tmp"
  fi
fi

# ---- STAGE 3: well-formedness check, BEFORE touching real files ------------
echo "Checking generated XML..."
if command -v xmllint >/dev/null 2>&1; then
  if [[ -f "${OSSEC_CONF}.tmp" ]]; then
    set +e
    OUT="$(xmllint --noout "${OSSEC_CONF}.tmp" 2>&1)"; RC=$?
    set -e
    if [[ $RC -ne 0 ]]; then
      echo "ERROR: generated ossec.conf is not well-formed XML — nothing written." >&2
      echo "$OUT" >&2
      rm -f "${OSSEC_CONF}.tmp" "${LOCAL_RULES}.tmp" 2>/dev/null
      exit 1
    fi
  fi
  if [[ -f "${LOCAL_RULES}.tmp" ]]; then
    { echo "<root>"; cat "${LOCAL_RULES}.tmp"; echo "</root>"; } > "${LOCAL_RULES}.tmp.wrapped"
    set +e
    OUT="$(xmllint --noout "${LOCAL_RULES}.tmp.wrapped" 2>&1)"; RC=$?
    set -e
    rm -f "${LOCAL_RULES}.tmp.wrapped"
    if [[ $RC -ne 0 ]]; then
      echo "ERROR: generated local_rules.xml is not well-formed XML — nothing written." >&2
      echo "$OUT" >&2
      rm -f "${OSSEC_CONF}.tmp" "${LOCAL_RULES}.tmp" 2>/dev/null
      exit 1
    fi
  fi
  echo "XML OK."
else
  echo "(xmllint not installed — skipped structural pre-check, will rely on Wazuh's own validator after write)"
fi

# ---- STAGE 4: everything checks out — NOW back up and apply ----------------
OSSEC_BACKUP=""
RULES_BACKUP=""
if [[ -f "${OSSEC_CONF}.tmp" ]]; then
  OSSEC_BACKUP="${OSSEC_CONF}.bak.$(date +%Y%m%d%H%M%S)"
  cp "$OSSEC_CONF" "$OSSEC_BACKUP"
  echo "Backup: $OSSEC_BACKUP"
  mv "${OSSEC_CONF}.tmp" "$OSSEC_CONF"
  [[ ${#REAL_NEW_LINES[@]} -gt 0 ]] && echo "${#REAL_NEW_LINES[@]} director$([ ${#REAL_NEW_LINES[@]} -eq 1 ] && echo y || echo ies) added to ossec.conf."
  [[ ${#REMOVE_PATH_SET[@]} -gt 0 ]] && echo "${#REMOVE_PATH_SET[@]} director$([ ${#REMOVE_PATH_SET[@]} -eq 1 ] && echo y || echo ies) removed from ossec.conf."
fi
if [[ -f "${LOCAL_RULES}.tmp" ]]; then
  RULES_BACKUP="${LOCAL_RULES}.bak.$(date +%Y%m%d%H%M%S)"
  cp "$LOCAL_RULES" "$RULES_BACKUP"
  echo "Backup: $RULES_BACKUP"
  mv "${LOCAL_RULES}.tmp" "$LOCAL_RULES"
  [[ ${#RULE_BLOCKS[@]} -gt 0 ]] && echo "${#RULE_BLOCKS[@]} new rule(s) added to local_rules.xml."
  [[ $NEED_ANY_EDIT -eq 1 ]] && echo "Existing rule(s) updated in local_rules.xml."
fi

# ---- validate live, roll back both on failure -------------------------------
echo "Validating..."
CHECKED=0
ATTEMPTED=0
if command -v /var/ossec/bin/wazuh-control >/dev/null 2>&1; then
  ATTEMPTED=1
  set +e
  OUT="$(/var/ossec/bin/wazuh-control configtest 2>&1)"; RC=$?
  set -e
  if echo "$OUT" | grep -qi "Usage:"; then
    :
  elif [[ $RC -eq 0 ]]; then
    echo "OK."
    CHECKED=1
  else
    echo "$OUT"
    echo "FAILED — restoring." >&2
    rollback_all
    exit 1
  fi
fi
if [[ $CHECKED -eq 0 ]] && command -v /var/ossec/bin/wazuh-analysisd >/dev/null 2>&1; then
  ATTEMPTED=1
  set +e
  OUT="$(/var/ossec/bin/wazuh-analysisd -t 2>&1)"; RC=$?
  set -e
  if [[ $RC -eq 0 ]]; then
    echo "OK (checked via wazuh-analysisd -t)."
    CHECKED=1
  else
    echo "$OUT"
    echo "FAILED — restoring." >&2
    rollback_all
    exit 1
  fi
fi
if [[ $CHECKED -eq 0 && $ATTEMPTED -eq 0 ]]; then
  echo "No config-test tool found — please verify manually before restarting:"
  echo "  /var/ossec/bin/wazuh-analysisd -t"
fi

read -rp "Restart Wazuh now to apply? y/n > " RS
RESTART_STATUS="not restarted (run: systemctl restart wazuh-manager)"
if [[ "$RS" =~ ^[Yy] ]]; then
  systemctl restart wazuh-manager
  echo "Restarted. Monitoring is now active."
  RESTART_STATUS="restarted, active now"
else
  echo "Not restarted yet — run this later: systemctl restart wazuh-manager"
fi

send_telegram_summary "$RESTART_STATUS"

exit 0
}

# ---- main menu ------------------------------------------------------------
START_PHASE=""
while true; do
    echo
    echo "=== FIM Directory Adder — Main Menu ==="
    echo "[1] Add paths to monitor"
    echo "[2] View monitored paths"
    echo "[3] Exit"
    read -rp "> " CHOICE
    MC="$(echo "$CHOICE" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    case "$MC" in
        1)
            ask_global_rule_once
            START_PHASE="add"
            break
            ;;
        2)
            GOTO_ADD=0
            view_monitored_menu
            if [[ $GOTO_ADD -eq 1 ]]; then
                ask_global_rule_once
                START_PHASE="add"
                break
            fi
            if [[ ${#SESSION_PATHS[@]} -gt 0 ]]; then
                START_PHASE="confirm"
                break
            fi
            ;;
        3|e|exit)
            if [[ ${#SESSION_PATHS[@]} -gt 0 ]]; then
                read -rp "You have queued changes not saved. Discard and exit? y/n > " DISC
                [[ "$DISC" =~ ^[Yy] ]] && exit 0
                continue
            fi
            exit 0
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
done

# ---- main step machine --------------------------------------------------
echo
echo "=== FIM Directory Adder ==="
echo "[E]xit  [D]elete  [R]eturn — available at every step"

PHASE="$START_PHASE"
STEP=1
PENDING_PATH=""
CUR_PATH="" CUR_EXTS=() CUR_RT="y" CUR_RC="y"
CUR_NEEDS_DIR_LINE=1
CUR_EDIT_ID=""
CUR_EXISTING_EXTS=()

finalize_entry() {
    local dirline="" ext_joined="" summary_ext=""

    if [[ $CUR_NEEDS_DIR_LINE -eq 1 ]]; then
        local rt_attr="" rc_attr="" ts by
        ts="$(date '+%Y-%m-%d %H:%M:%S')"
        by="$(get_added_by)"
        [[ "$CUR_RT" =~ ^[Yy] ]] && rt_attr=' realtime="yes"'
        [[ "$CUR_RC" =~ ^[Yy] ]] && rc_attr=' report_changes="yes"'
        dirline="    <!-- add_fim_dir.sh added ${ts} by ${by}: ${CUR_PATH} -->
    <directories check_all=\"yes\"${rc_attr}${rt_attr}>${CUR_PATH}</directories>"
    fi

    if [[ -n "$CUR_EDIT_ID" ]]; then
        local merged=($(printf "%s\n" "${CUR_EXISTING_EXTS[@]}" "${CUR_EXTS[@]}" | sort -u))
        ext_joined=$(IFS='|'; echo "${merged[*]}")
        summary_ext="$(printf '.%s ' "${merged[@]}")(updating rule ${CUR_EDIT_ID})"
    elif [[ ${#CUR_EXTS[@]} -eq 0 ]]; then
        ext_joined=""
        summary_ext="global rule only"
    else
        ext_joined=$(IFS='|'; echo "${CUR_EXTS[*]}")
        summary_ext="$(printf '.%s ' "${CUR_EXTS[@]}")(new per-directory rule)"
    fi

    NEW_LINES+=("$dirline")
    SESSION_PATHS+=("$CUR_PATH")
    RULE_EXTS+=("$ext_joined")
    EDIT_RULE_ID+=("$CUR_EDIT_ID")
    DELETE_RULE_ID+=("")
    DELETE_DIRLINE+=("")
    SUMMARY+=("${CUR_PATH} -> ${summary_ext}")
    echo "Added."

    CUR_PATH=""; CUR_EXTS=(); CUR_NEEDS_DIR_LINE=1; CUR_EDIT_ID=""; CUR_EXISTING_EXTS=()
    STEP=1; PHASE="confirm"
}

while true; do
  if [[ "$PHASE" == "add" ]]; then
    echo "----------------------------------------"
    case "$STEP" in
      1)
        if [[ -n "$PENDING_PATH" ]]; then
          IN="$PENDING_PATH"; PENDING_PATH=""
          echo "[1/4] Path (blank=done) > $IN"
        else
          read -rp "[1/4] Path (blank=done) > " IN
        fi
        c="$(classify "$IN")"
        [[ "$c" == "E" ]] && { echo "$(status)"; exit 0; }
        [[ "$c" == "D" ]] && { manage_delete; continue; }
        if [[ -z "$IN" ]]; then PHASE="confirm"; continue; fi
        if [[ ! -e "$IN" ]]; then
          read -rp "Not found. Continue? y/n > " CY
          c="$(classify "$CY")"
          [[ "$c" == "E" ]] && { echo "$(status)"; exit 0; }
          [[ "$c" == "D" || "$c" == "R" ]] && continue
          [[ "$CY" =~ ^[Yy] ]] || continue
        fi
        if path_queued "$IN"; then echo "Already queued this run — skipped."; continue; fi

        if path_monitored "$IN"; then
          FOUND="$(find_existing_rule "$IN" || true)"
          if [[ -n "$FOUND" ]]; then
            EXIST_ID="${FOUND%%|*}"
            EXIST_EXT="${FOUND#*|}"
            IFS='|' read -ra CUR_EXISTING_EXTS <<< "$EXIST_EXT"
            echo "Already monitored. Existing rule (ID ${EXIST_ID}) allows: $(printf '.%s ' "${CUR_EXISTING_EXTS[@]}")"
            read -rp "Add more extensions to it? y/n > " ADDMORE
            c="$(classify "$ADDMORE")"
            [[ "$c" == "E" ]] && { echo "$(status)"; exit 0; }
            [[ "$c" == "D" || "$c" == "R" ]] && continue
            if [[ ! "$ADDMORE" =~ ^[Yy] ]]; then echo "Skipped."; continue; fi
            CUR_PATH="${IN%/}"; CUR_NEEDS_DIR_LINE=0; CUR_EDIT_ID="$EXIST_ID"
            STEP=2
          else
            echo "Already monitored, no per-directory filter set (relies on global rule)."
            read -rp "Add a per-directory filter for it now? y/n > " ADDNEW
            c="$(classify "$ADDNEW")"
            [[ "$c" == "E" ]] && { echo "$(status)"; exit 0; }
            [[ "$c" == "D" || "$c" == "R" ]] && continue
            if [[ ! "$ADDNEW" =~ ^[Yy] ]]; then echo "Skipped."; continue; fi
            CUR_PATH="${IN%/}"; CUR_NEEDS_DIR_LINE=0; CUR_EDIT_ID=""; CUR_EXISTING_EXTS=()
            STEP=2
          fi
          continue
        fi

        CUR_PATH="${IN%/}"; CUR_NEEDS_DIR_LINE=1; CUR_EDIT_ID=""; CUR_EXISTING_EXTS=()
        STEP=2
        ;;
      2)
        if [[ -n "$CUR_EDIT_ID" ]]; then
          echo "Currently monitored on: $(printf '.%s ' "${CUR_EXISTING_EXTS[@]}")"
          echo "Ex: (pick numbers, Example: 1 2 4, or all = add every extension listed):"
        else
          echo "Ex: (pick numbers, Example: 1 2 4, custom:conf,cfg, all = add every extension listed, global = rely on global rule only):"
        fi
        COL=0
        for i in $(seq 1 ${#EXT_MENU[@]}); do
          SKIP=0
          if [[ -n "$CUR_EDIT_ID" ]]; then
            for e in "${CUR_EXISTING_EXTS[@]}"; do
              [[ "${EXT_MENU[$i]}" == "$e" ]] && { SKIP=1; break; }
            done
          fi
          [[ $SKIP -eq 1 ]] && continue
          printf "%2d=%-9s" "$i" "${EXT_MENU[$i]}"
          COL=$((COL+1))
          (( COL % 5 == 0 )) && echo
        done
        echo
        read -rp "[2/4] Ext > " IN
        c="$(classify "$IN")"
        [[ "$c" == "E" ]] && { echo "$(status)"; exit 0; }
        [[ "$c" == "R" ]] && { STEP=1; continue; }
        [[ "$c" == "D" ]] && { manage_delete; continue; }

        LOW="$(echo "$IN" | tr '[:upper:]' '[:lower:]' | tr -d "[:space:]'\"")"
        if [[ "$LOW" == "global" && $CUR_NEEDS_DIR_LINE -eq 1 && -z "$CUR_EDIT_ID" ]]; then
          CUR_EXTS=()
          finalize_entry
          continue
        fi

        SEL=()
        if [[ "$LOW" == "all" ]]; then
          for i in $(seq 1 ${#EXT_MENU[@]}); do
            SKIP=0
            if [[ -n "$CUR_EDIT_ID" ]]; then
              for e in "${CUR_EXISTING_EXTS[@]}"; do
                [[ "${EXT_MENU[$i]}" == "$e" ]] && { SKIP=1; break; }
              done
            fi
            [[ $SKIP -eq 0 ]] && SEL+=("${EXT_MENU[$i]}")
          done
        else
          IN_NUMS="${IN//,/ }"
          for tok in $IN_NUMS; do
            [[ "$tok" =~ ^[0-9]+$ && -n "${EXT_MENU[$tok]:-}" ]] && SEL+=("${EXT_MENU[$tok]}")
          done
          if [[ "$IN" =~ custom:[[:space:]]*([a-zA-Z0-9,._-]+) ]]; then
            IFS=',' read -ra CA <<< "${BASH_REMATCH[1]}"
            for e in "${CA[@]}"; do
              e="$(echo "$e" | tr -d '[:space:]' | sed 's/^\.*//')"
              [[ -n "$e" ]] && SEL+=("$e")
            done
          fi
        fi
        if [[ ${#SEL[@]} -eq 0 ]]; then echo "No valid ext."; continue; fi

        FINAL=() ; BLOCKED=()
        for e in "${SEL[@]}"; do
          if is_noisy "$e"; then BLOCKED+=("$e"); else FINAL+=("$e"); fi
        done
        FINAL=($(printf "%s\n" "${FINAL[@]}" | sort -u))
        [[ ${#BLOCKED[@]} -gt 0 ]] && echo "Blocked (already covered by global noise rule): $(printf '.%s ' "${BLOCKED[@]}")"
        if [[ ${#FINAL[@]} -eq 0 ]]; then echo "All blocked — try again."; continue; fi

        CUR_EXTS=("${FINAL[@]}")

        if [[ $CUR_NEEDS_DIR_LINE -eq 0 ]]; then
          # Editing/adding a rule for an already-monitored path — nothing
          # else to ask, the directory line and its realtime/report
          # settings already exist.
          finalize_entry
        else
          STEP=3
        fi
        ;;
      3)
        read -rp "[3/4] Realtime? y/n [y] > " IN
        c="$(classify "$IN")"
        [[ "$c" == "E" ]] && { echo "$(status)"; exit 0; }
        [[ "$c" == "D" ]] && { manage_delete; continue; }
        [[ "$c" == "R" ]] && { STEP=2; continue; }
        CUR_RT="${IN:-y}"
        STEP=4
        ;;
      4)
        read -rp "[4/4] Verify changes? y/n [y] > " IN
        c="$(classify "$IN")"
        [[ "$c" == "E" ]] && { echo "$(status)"; exit 0; }
        [[ "$c" == "D" ]] && { manage_delete; continue; }
        [[ "$c" == "R" ]] && { STEP=3; continue; }
        CUR_RC="${IN:-y}"
        finalize_entry
        ;;
    esac

  else  # PHASE == confirm
    if [[ ${#SESSION_PATHS[@]} -eq 0 && $NEED_GLOBAL_RULE -eq 0 ]]; then
      echo "Nothing queued."; exit 0
    fi
    echo "========================================"
    if [[ $NEED_GLOBAL_RULE -eq 1 ]]; then
      echo " * Global noise-suppression rule (once, covers all paths)"
    fi
    for i in "${!SUMMARY[@]}"; do
      printf "%2d) %s\n" "$((i+1))" "${SUMMARY[$i]}"
      [[ -n "${NEW_LINES[$i]}" ]] && printf "    %s\n" "$(echo "${NEW_LINES[$i]}" | sed 's/^ *//')"
      if [[ -n "${RULE_EXTS[$i]}" ]]; then
        if [[ -n "${EDIT_RULE_ID[$i]}" ]]; then
          printf "    ~ local_rules.xml: updating existing rule %s\n" "${EDIT_RULE_ID[$i]}"
        else
          printf "    + local_rules.xml: new rule (auto-ID)\n"
        fi
      fi
      [[ -n "${DELETE_RULE_ID[$i]}" ]] && printf "    - local_rules.xml: deleting existing rule %s\n" "${DELETE_RULE_ID[$i]}"
      [[ "${DELETE_DIRLINE[$i]}" == "1" ]] && printf "    - ossec.conf: removing <directories> line entirely\n"
    done
    echo "----------------------------------------"
    read -rp "${#SESSION_PATHS[@]} dir(s) queued — [C]ontinue  [S]ave  [D]elete#  [E]xit > " IN
    c="$(classify "$IN")"
    v="$(echo "$IN" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    if [[ "$c" == "E" ]]; then echo "Cancelled. $(status)"; exit 0; fi
    if [[ "$c" == "R" ]]; then PHASE="add"; STEP=1; continue; fi
    if [[ "$c" == "D" ]]; then
      manage_delete
      continue
    fi
    if [[ "$v" == "s" || "$v" == "save" || "$v" =~ ^y ]]; then perform_save; fi
    if [[ -z "$IN" ]]; then continue; fi
    PENDING_PATH="$IN"; PHASE="add"; STEP=1; continue
  fi
done