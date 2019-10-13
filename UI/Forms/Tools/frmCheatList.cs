﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Mesen.GUI.Config;
using Mesen.GUI.Debugger;
using Mesen.GUI.Properties;

namespace Mesen.GUI.Forms
{
	public partial class frmCheatList : BaseConfigForm
	{
		private List<CheatCode> _cheats;
		private NotificationListener _notifListener;

		public frmCheatList()
		{
			InitializeComponent();
		}

		private static frmCheatList _instance = null;
		public static void ShowWindow()
		{
			if(_instance != null) {
				DebugWindowManager.BringToFront(_instance);
			}
			frmCheatList frm = new frmCheatList();
			_instance = frm;
			frm.Closed += (s, e) => { _instance = null; };
			frm.Show(null, Application.OpenForms[0]);
		}
		
		protected override void OnLoad(EventArgs e)
		{
			base.OnLoad(e);
			if(!DesignMode) {
				this.Icon = Resources.CheatCode;

				_notifListener = new NotificationListener();
				_notifListener.OnNotification += OnNotification;

				InitCheatList();
				UpdateMenuItems();
				chkDisableCheats.Checked = ConfigManager.Config.Cheats.DisableAllCheats;
				RestoreLocation(ConfigManager.Config.Cheats.WindowLocation, ConfigManager.Config.Cheats.WindowSize);
			}
		}

		private void InitCheatList()
		{
			_cheats = new List<CheatCode>(CheatCodes.LoadCheatCodes().Cheats);
			UpdateCheatList();
		}

		private void OnNotification(NotificationEventArgs e)
		{
			switch(e.NotificationType) {
				case ConsoleNotificationType.GameLoaded:
					this.BeginInvoke((Action)(() => {
						InitCheatList();
					}));
					break;

				case ConsoleNotificationType.BeforeEmulationStop:
					this.Invoke((Action)(() => {
						Close();
					}));
					break;
			}
		}

		protected override void OnClosing(CancelEventArgs e)
		{
			base.OnClosing(e);
			_notifListener?.Dispose();

			ConfigManager.Config.Cheats.WindowLocation = this.WindowState != FormWindowState.Normal ? this.RestoreBounds.Location : this.Location;
			ConfigManager.Config.Cheats.WindowSize = this.WindowState != FormWindowState.Normal ? this.RestoreBounds.Size : this.Size;

			if(this.DialogResult == DialogResult.OK) {
				ConfigManager.Config.Cheats.DisableAllCheats = chkDisableCheats.Checked;
				(new CheatCodes() { Cheats = _cheats }).Save();
			}
			ConfigManager.ApplyChanges();
			CheatCodes.ApplyCheats();
		}

		protected override void OnShown(EventArgs e)
		{
			base.OnShown(e);
			ResizeColumns();
		}

		protected override void OnResizeEnd(EventArgs e)
		{
			base.OnResizeEnd(e);
			ResizeColumns();
		}

		private void ResizeColumns()
		{
			colCodes.Width = lstCheats.ClientSize.Width - colEnabled.Width - colCheatName.Width - 10;
		}

		private void ApplyCheats()
		{
			if(chkDisableCheats.Checked) {
				EmuApi.ClearCheats();
			} else {
				CheatCodes.ApplyCheats(_cheats);
			}
		}

		private void UpdateCheatList()
		{
			lstCheats.BeginUpdate();
			lstCheats.Sorting = SortOrder.None;
			lstCheats.Items.Clear();
			lstCheats.ItemChecked -= lstCheats_ItemChecked;

			foreach(CheatCode cheat in _cheats) {
				ListViewItem item = lstCheats.Items.Add("");
				item.SubItems.Add(string.IsNullOrWhiteSpace(cheat.Description) ? "[n/a]" : cheat.Description);
				item.SubItems.Add(cheat.ToString());
				item.Tag = cheat;
				item.Checked = cheat.Enabled;
			}

			lstCheats.Sorting = SortOrder.Ascending;
			lstCheats.ItemChecked += lstCheats_ItemChecked;
			lstCheats.EndUpdate();

			ResizeColumns();
		}

		private void mnuAddCheat_Click(object sender, EventArgs e)
		{
			CheatCode newCheat = new CheatCode() { Enabled = true };

			using(frmCheat frm = new frmCheat(newCheat)) {
				if(frm.ShowDialog(this) == DialogResult.OK) {
					AddCheats(new List<CheatCode>() { newCheat });
				}
			}
		}

		private void EditCheat()
		{
			if(lstCheats.SelectedItems.Count == 1) {
				using(frmCheat frm = new frmCheat((CheatCode)lstCheats.SelectedItems[0].Tag)) {
					if(frm.ShowDialog(this) == DialogResult.OK) {
						UpdateCheatList();
						ApplyCheats();
					}
				}
			}
		}

		private void lstCheats_DoubleClick(object sender, EventArgs e)
		{
			EditCheat();
		}

		private void lstCheats_ItemChecked(object sender, ItemCheckedEventArgs e)
		{
			if(e.Item.Tag is CheatCode) {
				((CheatCode)e.Item.Tag).Enabled = e.Item.Checked;
				ApplyCheats();
				lstCheats.SelectedItems.Clear();
			}
		}

		private void lstCheats_SelectedIndexChanged(object sender, EventArgs e)
		{
			UpdateMenuItems();
		}

		private void UpdateMenuItems()
		{
			mnuDeleteCheat.Enabled = btnDeleteCheat.Enabled = lstCheats.SelectedItems.Count > 0;
			mnuEditCheat.Enabled = btnEditCheat.Enabled = lstCheats.SelectedItems.Count == 1;
		}

		private void DeleteSelectedCheats()
		{
			if(lstCheats.SelectedItems.Count > 0) {
				foreach(ListViewItem item in lstCheats.SelectedItems) {
					CheatCode cheat = item.Tag as CheatCode;
					_cheats.Remove(cheat);
				}
				ApplyCheats();
				UpdateCheatList();
			}
		}

		private void btnDeleteCheat_Click(object sender, EventArgs e)
		{
			DeleteSelectedCheats();
		}

		private void AddCheats(List<CheatCode> cheats)
		{
			if(cheats.Count > 0) {
				foreach(CheatCode cheat in cheats) {
					_cheats.Add(cheat);
				}
				UpdateCheatList();
				ApplyCheats();
			}
		}
		
		private void chkDisableCheats_CheckedChanged(object sender, EventArgs e)
		{
			ApplyCheats();
		}

		private void mnuEditCheat_Click(object sender, EventArgs e)
		{
			EditCheat();
		}
	}
}
