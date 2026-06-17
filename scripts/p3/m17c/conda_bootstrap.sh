# Shared conda bootstrap for cron / non-interactive shell.
# Auto-generated on 2026-06-04T07:18:30Z

CONDA_BASE="/home/zhangxiaohui/installers/ENTER"

if [ -f "$CONDA_BASE/etc/profile.d/conda.sh" ]; then
  source "$CONDA_BASE/etc/profile.d/conda.sh"
elif [ -f "$HOME/miniconda3/etc/profile.d/conda.sh" ]; then
  source "$HOME/miniconda3/etc/profile.d/conda.sh"
elif [ -f "$HOME/anaconda3/etc/profile.d/conda.sh" ]; then
  source "$HOME/anaconda3/etc/profile.d/conda.sh"
elif [ -f "$HOME/miniforge3/etc/profile.d/conda.sh" ]; then
  source "$HOME/miniforge3/etc/profile.d/conda.sh"
elif [ -f "$HOME/mambaforge/etc/profile.d/conda.sh" ]; then
  source "$HOME/mambaforge/etc/profile.d/conda.sh"
else
  echo "CONDA_INIT_FAILED: conda.sh not found"
  echo "CONDA_BASE=$CONDA_BASE"
  echo "HOME=$HOME"
  exit 1
fi

conda activate s3-radar
