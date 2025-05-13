<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pathshala Election System</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-50">
    <div class="container mx-auto px-4 py-8 max-w-4xl">
        <header class="flex flex-col md:flex-row items-center justify-between mb-10 border-b pb-6">
            <div class="flex items-center mb-4 md:mb-0">
                <img src="/api/placeholder/150/150" alt="Pathshala Logo" class="h-20 mr-4">
                <div>
                    <h1 class="text-3xl font-bold text-blue-800">Pathshala Election System</h1>
                    <p class="text-gray-600 mt-1">
                        Developed by <a href="https://dhunganapradip.com.np" class="text-blue-600 hover:underline">Pradip Dhungana</a>
                    </p>
                </div>
            </div>
            <div class="flex space-x-2">
                <a href="https://github.com/dhunganaPradeep/Pathshala-Election" class="bg-gray-800 hover:bg-gray-700 text-white px-4 py-2 rounded-md flex items-center">
                    <i class="fab fa-github mr-2"></i> GitHub
                </a>
                <a href="https://pathshala.edu.np/" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md flex items-center">
                    <i class="fas fa-school mr-2"></i> Pathshala
                </a>
            </div>
        </header>

        <section class="mb-10">
            <p class="text-lg text-gray-700 leading-relaxed">
                A comprehensive election management system designed specifically for <strong>Pathshala Nepal Foundation</strong>. 
                This application facilitates fair and transparent elections for student leadership positions within the school environment.
            </p>
        </section>

        <section class="mb-12">
            <h2 class="text-2xl font-bold text-blue-800 mb-4 border-b pb-2">Key Features</h2>
            <div class="grid md:grid-cols-2 gap-6">
                <div class="bg-white p-6 rounded-lg shadow">
                    <div class="flex items-center mb-3">
                        <i class="fas fa-shield-alt text-green-600 text-xl mr-3"></i>
                        <h3 class="text-xl font-semibold">Secure Voting</h3>
                    </div>
                    <p class="text-gray-600">Each student receives a unique voting code to ensure one vote per student.</p>
                </div>
                
                <div class="bg-white p-6 rounded-lg shadow">
                    <div class="flex items-center mb-3">
                        <i class="fas fa-tachometer-alt text-purple-600 text-xl mr-3"></i>
                        <h3 class="text-xl font-semibold">Admin Dashboard</h3>
                    </div>
                    <p class="text-gray-600">Real-time monitoring of election progress with comprehensive analytics.</p>
                </div>
                
                <div class="bg-white p-6 rounded-lg shadow">
                    <div class="flex items-center mb-3">
                        <i class="fas fa-mobile-alt text-blue-600 text-xl mr-3"></i>
                        <h3 class="text-xl font-semibold">Mobile Friendly</h3>
                    </div>
                    <p class="text-gray-600">Responsive design allows students to vote from any device, anywhere.</p>
                </div>
                
                <div class="bg-white p-6 rounded-lg shadow">
                    <div class="flex items-center mb-3">
                        <i class="fas fa-balance-scale text-red-600 text-xl mr-3"></i>
                        <h3 class="text-xl font-semibold">Gender Balance</h3>
                    </div>
                    <p class="text-gray-600">Support for electing both male and female candidates, ensuring representation.</p>
                </div>
                
                <div class="bg-white p-6 rounded-lg shadow">
                    <div class="flex items-center mb-3">
                        <i class="fas fa-cog text-yellow-600 text-xl mr-3"></i>
                        <h3 class="text-xl font-semibold">Vote Management</h3>
                    </div>
                    <p class="text-gray-600">Administrators can revoke votes or reset the election if needed.</p>
                </div>
                
                <div class="bg-white p-6 rounded-lg shadow">
                    <div class="flex items-center mb-3">
                        <i class="fas fa-chart-bar text-indigo-600 text-xl mr-3"></i>
                        <h3 class="text-xl font-semibold">Results Analysis</h3>
                    </div>
                    <p class="text-gray-600">View detailed voting statistics with class-wise breakdowns and exportable reports.</p>
                </div>
            </div>
        </section>

        <section class="mb-12">
            <h2 class="text-2xl font-bold text-blue-800 mb-4 border-b pb-2">Tech Stack</h2>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div class="bg-white p-4 rounded-lg shadow text-center">
                    <i class="fab fa-python text-blue-500 text-3xl mb-2"></i>
                    <p class="font-medium">Python with Flask</p>
                </div>
                <div class="bg-white p-4 rounded-lg shadow text-center">
                    <i class="fas fa-database text-gray-700 text-3xl mb-2"></i>
                    <p class="font-medium">SQLite Database</p>
                </div>
                <div class="bg-white p-4 rounded-lg shadow text-center">
                    <i class="fab fa-html5 text-red-500 text-3xl mb-2"></i>
                    <p class="font-medium">HTML/CSS with Tailwind</p>
                </div>
                <div class="bg-white p-4 rounded-lg shadow text-center">
                    <i class="fab fa-js text-yellow-500 text-3xl mb-2"></i>
                    <p class="font-medium">JavaScript with jQuery</p>
                </div>
            </div>
        </section>

        <section class="mb-12">
            <h2 class="text-2xl font-bold text-blue-800 mb-4 border-b pb-2">Setup Guide</h2>
            
            <div class="mb-6">
                <h3 class="text-xl font-semibold mb-3">Prerequisites</h3>
                <ul class="list-disc list-inside space-y-2 text-gray-700 ml-4">
                    <li>Python 3.7 or higher</li>
                    <li>pip (Python package manager)</li>
                </ul>
            </div>
            
            <div class="mb-6">
                <h3 class="text-xl font-semibold mb-3">Installation Steps</h3>
                <div class="bg-gray-800 rounded-lg p-4 mb-4">
                    <p class="text-white mb-2 font-semibold">1. Clone the repository</p>
                    <pre class="bg-gray-900 p-3 rounded text-green-400 overflow-x-auto">git clone https://github.com/dhunganaPradeep/Pathshala-Election.git
cd Pathshala-Election</pre>
                </div>
                
                <div class="bg-gray-800 rounded-lg p-4 mb-4">
                    <p class="text-white mb-2 font-semibold">2. Create and activate a virtual environment</p>
                    <pre class="bg-gray-900 p-3 rounded text-green-400 overflow-x-auto">python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate</pre>
                </div>
                
                <div class="bg-gray-800 rounded-lg p-4 mb-4">
                    <p class="text-white mb-2 font-semibold">3. Install dependencies</p>
                    <pre class="bg-gray-900 p-3 rounded text-green-400 overflow-x-auto">pip install -r requirements.txt</pre>
                </div>
                
                <div class="bg-gray-800 rounded-lg p-4 mb-4">
                    <p class="text-white mb-2 font-semibold">4. Initialize the database</p>
                    <pre class="bg-gray-900 p-3 rounded text-green-400 overflow-x-auto">python -c "from app import init_db; init_db()"</pre>
                </div>
                
                <div class="bg-gray-800 rounded-lg p-4 mb-4">
                    <p class="text-white mb-2 font-semibold">5. Run the application</p>
                    <pre class="bg-gray-900 p-3 rounded text-green-400 overflow-x-auto">python app.py</pre>
                </div>
                
                <div class="bg-white border border-gray-200 rounded-lg p-4">
                    <p class="font-semibold mb-2">6. Access the application</p>
                    <ul class="list-disc list-inside space-y-2 text-gray-700 ml-4">
                        <li>Main voting page: <code class="bg-gray-100 px-2 py-1 rounded">http://localhost:5000</code></li>
                        <li>Admin panel: <code class="bg-gray-100 px-2 py-1 rounded">http://localhost:5000/admin</code></li>
                        <li>Default admin credentials:
                            <ul class="list-disc list-inside ml-6">
                                <li>Username: <code class="bg-gray-100 px-2 py-1 rounded">admin</code></li>
                                <li>Password: <code class="bg-gray-100 px-2 py-1 rounded">admin</code></li>
                            </ul>
                        </li>
                    </ul>
                </div>
            </div>
        </section>

        <section class="mb-12">
            <h2 class="text-2xl font-bold text-blue-800 mb-4 border-b pb-2">Production Deployment</h2>
            <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4 mb-6">
                <div class="flex">
                    <div class="flex-shrink-0">
                        <i class="fas fa-exclamation-triangle text-yellow-400"></i>
                    </div>
                    <div class="ml-3">
                        <p class="text-sm text-yellow-700">
                            For security in production environments, we recommend the following measures.
                        </p>
                    </div>
                </div>
            </div>
            <ul class="list-disc list-inside space-y-2 text-gray-700 ml-4">
                <li>Using a WSGI server like Gunicorn or uWSGI</li>
                <li>Setting up a reverse proxy with Nginx or Apache</li>
                <li>Ensuring all security headers are properly configured</li>
                <li>Running on HTTPS only</li>
                <li>Setting strong, unique values for all secret keys</li>
            </ul>
        </section>

        <section class="mb-12">
            <h2 class="text-2xl font-bold text-blue-800 mb-4 border-b pb-2">Usage Guide</h2>
            
            <div class="grid md:grid-cols-2 gap-8">
                <div class="bg-white p-6 rounded-lg shadow">
                    <h3 class="text-xl font-semibold mb-4 text-blue-700">
                        <i class="fas fa-user-shield mr-2"></i>For Administrators
                    </h3>
                    <ol class="list-decimal list-inside space-y-3 text-gray-700">
                        <li>Upload student data via Excel spreadsheet</li>
                        <li>Upload or manually add teacher accounts via Excel</li>
                        <li>Add election candidates with photos and manifestos</li>
                        <li>Generate and distribute voting codes</li>
                        <li>Monitor voting progress in real-time</li>
                        <li>View and export detailed results</li>
                    </ol>
                </div>
                
                <div class="bg-white p-6 rounded-lg shadow">
                    <h3 class="text-xl font-semibold mb-4 text-blue-700">
                        <i class="fas fa-users mr-2"></i>For Voters
                    </h3>
                    <ol class="list-decimal list-inside space-y-3 text-gray-700">
                        <li>Enter the provided unique voting code</li>
                        <li>View candidate profiles and manifestos</li>
                        <li>Select one male and one female candidate</li>
                        <li>Review your selections</li>
                        <li>Submit your vote securely</li>
                    </ol>
                </div>
            </div>
        </section>

        <section class="mb-12">
            <h2 class="text-2xl font-bold text-blue-800 mb-4 border-b pb-2">Data Management</h2>
            <div class="bg-white p-6 rounded-lg shadow">
                <h3 class="text-xl font-semibold mb-4">Excel Upload Templates</h3>
                <p class="mb-4 text-gray-700">The system supports bulk data uploads using Excel templates for:</p>
                
                <div class="grid md:grid-cols-2 gap-4 mb-6">
                    <div class="border border-gray-200 rounded-md p-4">
                        <h4 class="font-medium text-lg mb-2">Student Template</h4>
                        <p class="text-sm text-gray-600 mb-2">Required columns:</p>
                        <ul class="list-disc list-inside text-sm text-gray-600">
                            <li>Name</li>
                            <li>Class</li>
                            <li>Section</li>
                            <li>Roll Number</li>
                        </ul>
                    </div>
                    
                    <div class="border border-gray-200 rounded-md p-4">
                        <h4 class="font-medium text-lg mb-2">Teacher Template</h4>
                        <p class="text-sm text-gray-600 mb-2">Required columns:</p>
                        <ul class="list-disc list-inside text-sm text-gray-600">
                            <li>Name</li>
                            <li>Email</li>
                            <li>Department</li>
                            <li>Access Level</li>
                        </ul>
                    </div>
                </div>
                
                <div class="bg-blue-50 border-l-4 border-blue-400 p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <i class="fas fa-info-circle text-blue-400"></i>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm text-blue-700">
                                Sample Excel templates are included in the <code class="bg-blue-100 px-1">templates/</code> directory of the project.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section class="mb-12">
            <h2 class="text-2xl font-bold text-blue-800 mb-4 border-b pb-2">Screenshots</h2>
            <div class="bg-gray-100 p-8 rounded-lg text-center">
                <i class="fas fa-images text-gray-400 text-5xl mb-4"></i>
                <p class="text-gray-600">Coming soon...</p>
            </div>
        </section>

        <footer class="mt-12 pt-6 border-t border-gray-200">
            <div class="flex flex-col md:flex-row justify-between items-center">
                <p class="text-gray-600 mb-4 md:mb-0">
                    © 2023 Pathshala Election System. Licensed under the MIT License.
                </p>
                <div class="flex space-x-4">
                    <a href="https://github.com/dhunganaPradeep/Pathshala-Election" class="text-gray-600 hover:text-gray-900">
                        <i class="fab fa-github text-xl"></i>
                    </a>
                    <a href="https://dhunganapradip.com.np" class="text-gray-600 hover:text-gray-900">
                        <i class="fas fa-globe text-xl"></i>
                    </a>
                </div>
            </div>
        </footer>
    </div>
</body>
</html>
