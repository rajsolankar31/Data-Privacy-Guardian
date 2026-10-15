
from src import (
    detect_sensitive_data,
    apply_protection,
    calculate_risk_assessment,
    evaluate_utility,
    generate_markdown_report,
    scan_document,
    generate_synthetic_dataset,
)

from src.connectors.sqlite_connector import inspect_sqlite_database

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO
import os
import json
