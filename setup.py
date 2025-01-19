from setuptools import setup, find_packages

setup(
    name="project1.4",  # اسم الحزمة
    version="0.1",      # إصدار الحزمة
    packages=find_packages(),  # العثور تلقائيًا على جميع الحزم الفرعية
    install_requires=[],  # قائمة بالاعتماديات (إن وجدت)
    author="osama",   # اسم المؤلف
    author_email="osamakassab95@gmail.com",  # بريد المؤلف
    description="A project for university course",  # وصف الحزمة
    long_description="",  # ترك الوصف الطويل فارغًا
    long_description_content_type="text/markdown",  # نوع الوصف الطويل
    url="https://github.com/yourusername/project1.4",  # رابط المشروع (إن وجد)
)