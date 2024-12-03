
<%-- 
    Document   : Home
    Created on : 30-Oct-2024, 8:41:09 pm
    Author     : MMallick
--%>

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container-fluid">
            <div class="row">
                <!-- Sidebar -->
                <div class="col-md-2 bg-dark text-white p-3">
                    <h4>Dashboard</h4>
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link text-white" href="#">Home</a>
                        </li>
                        <li class="nav-item">
                              <a href="/questdemo/profile" class="dropdown-item dropdown-profile">
                            <a class="nav-link text-white" href="#">Profile</a>
                        </li>
                        <li class="nav-item">
                            <form action="/questdemo/logout" method="post">
                                <button class="btn btn-primary btn-block" type="submit">Logout</button>
                            </form>

                        </li>
                    </ul>
                </div>

                <!-- Main content -->
                <div class="col-md-10 p-4">
                    <h2>Welcome,<h2><h1>${username}!</h1> <!-- Assuming you have user details in session -->
                            <p><strong>Authorities:</strong> ${authorities}</p>
                            <p><strong>Auth Type:</strong> <b>${authtype}</b></p>
                            <p class="lead">You are logged in and ready to go.</p>

<!--                            <div class="row">
                                <div class="col-md-4">
                                    <div class="card">
                                        <div class="card-body">
                                            <h5 class="card-title">Dashboard Overview</h5>
                                            <p class="card-text">Quick glance at your account details.</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="card">
                                        <div class="card-body">
                                            <h5 class="card-title">Recent Activity</h5>
                                            <p class="card-text">Check out your latest activities.</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="card">
                                        <div class="card-body">
                                            <h5 class="card-title">Notifications</h5>
                                            <p class="card-text">New updates on your profile and account.</p>
                                        </div>
                                    </div>
                                </div>-->
                            </div>
                            </div>
                            </div>
                            </div>

                            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
                            </body>
                            </html>
