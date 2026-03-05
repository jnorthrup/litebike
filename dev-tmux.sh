#!/bin/bash
# Dual-pane tmux setup for ModelMux development

SESSION="modelmux-dev"

# Kill existing session if exists
tmux kill-session -t $SESSION 2>/dev/null || true

# Create new session
tmux new-session -d -s $SESSION -n "dev"

# Split vertically into two panes
tmux split-window -h -t $SESSION

# Left pane: Build and watch
tmux send-keys -t $SESSION:0.0 "cd /Users/jim/work/litebike" Enter
tmux send-keys -t $SESSION:0.0 "echo '=== LEFT: Build & Test ==='" Enter
tmux send-keys -t $SESSION:0.0 "cargo build --bin modelmux 2>&1 | tail -20" Enter

# Right pane: Run modelmux server
tmux send-keys -t $SESSION:0.1 "cd /Users/jim/work/litebike" Enter
tmux send-keys -t $SESSION:0.1 "echo '=== RIGHT: modelmux Server ==='" Enter
tmux send-keys -t $SESSION:0.1 "./target/debug/modelmux 2>&1" Enter

# Attach to session
tmux attach-session -t $SESSION
