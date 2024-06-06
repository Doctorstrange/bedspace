from flask import render_template, Blueprint, url_for, flash, redirect, request, g, jsonify

users = Blueprint("users", __name__)


