import subprocess
from kivy.app import App
from kivy.uix.popup import Popup
from kivy.uix.tabbedpanel import TabbedPanel
from kivy.properties import ObjectProperty, StringProperty
from kivy.lang import Builder
from kivy.core.text import LabelBase
import searchCVE
import re
from kivy.config import Config

Config.set('graphics', 'resizable', False)

kv = Builder.load_file("main.kv")
LabelBase.register(name="lemon", fn_regular="fonts/LemonMilk.otf")

class FileChoosePopup(Popup):
    load = ObjectProperty()

class MainWindow(TabbedPanel):
    file_path = StringProperty ("You should select a .csv file")
    the_popup = ObjectProperty (None)
    report = ""

    def open_popup(self):
        self.the_popup = FileChoosePopup(load=self.load)
        self.the_popup.open()
        self.ids.generate_report.disabled = True
        self.ids.report_word.disabled = True
        self.ids.report_csv.disabled = True
        self.ids.update_label.opacity = 0
        self.ids.gif.opacity = 0

    def load(self, selection):
        self.the_popup.dismiss()
        m = re.search ('\w+(?:\.\w+)*.csv$', str(selection[0]))
        if bool(m):
            self.file_path = m.group(0)
            self.ids.generate_report.disabled = False
        else:
            self.file_path="You should select a .csv file"

        # check for non-empty list i.e. file selected
        if self.file_path:
            self.ids.get_file.text = self.file_path

    def generate(self):
        self.ids.gif.source = "images/balls.gif"
        self.ids.update_label.text = "Generating Report..."
        self.ids.update_label.opacity = 1
        self.ids.gif.opacity = 1
        self.report = searchCVE.process_inventory(self.file_path)
        self.ids.report_word.disabled = False
        self.ids.report_csv.disabled = False
        self.ids.gif.source = "images/check.png"
        self.ids.update_label.text = "Report Successfully Generated!"
        self.ids.generate_report.disabled = True


    def openWord(self):
        report_word = self.report + ".docx"
        subprocess.run (['open', report_word], check=True)

    def openCSV(self):
        report_csv = self.report + ".csv"
        subprocess.run (['open', report_csv], check=True)

    def update(self):
        self.ids.update_label.text = "Updating..."
        self.ids.gif.source = "images/balls.gif"
        self.ids.update_label.opacity = 1
        self.ids.gif.opacity = 1
        self.ids.update_button.disabled = True
        searchCVE.update()
        self.ids.gif.source = "images/check.png"
        self.ids.update_label.text = "Database Successfully Updated!"

class GUI(App):
    def build(self):
        return MainWindow()

if __name__ == "__main__":
    GUI().run()
